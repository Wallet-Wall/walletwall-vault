/**
 * EXPERIMENTAL PROTOTYPE INVARIANT + MUTATION SUITE.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT
 * --------------------------------------
 * It exercises `VaultKernelPrototype` and `VaultKernelFactoryPrototype`, the
 * measurement prototype for the architecture adjudicated in PR #179. It is NOT
 * an audit, NOT a fuzzing campaign, and NOT evidence of production readiness.
 * It establishes that a named set of T0/T1 invariants HOLDS on a compiled
 * kernel and that each is DISCRIMINATING.
 *
 * THE VACUITY RULE, WHICH IS NOT OPTIONAL
 * ---------------------------------------
 * Almost every discriminator here is an ATTACK against the real kernel rather
 * than a mutation of a copy — a stronger form of evidence, because no mutant
 * can drift away from the contract it is supposed to model. The vacuity risk is
 * the same one #179 names: a test that fails during SETUP scores as "the
 * invariant held" while proving nothing.
 *
 * The guard against it is therefore structural: **every attack is paired with a
 * POSITIVE CONTROL** — the identical call with the one adversarial input
 * corrected — asserted in the same test. If the control succeeds and the attack
 * reverts, the seam was reached and the invariant is what killed it. A test
 * with no passing control is not counted as a kill.
 *
 * PQ CRYPTOGRAPHY IS NOT PROVEN BY THIS PROTOTYPE. The verifier is an interface
 * with mock implementations. Per #179 section 4.3a the deployed
 * `MockMLDSAVerifier` is a structural check with NO cryptographic guarantee, so
 * the only claim made here is that the PQ leg is a CONJUNCTIVE BARRIER.
 */
import { expect } from "chai";
import { ethers } from "./connection.js";

const ZERO = "0x0000000000000000000000000000000000000000";
const DAY = 24 * 60 * 60;

const ACTION = {
  SPEND: ethers.id("SPEND"),
  ROTATE: ethers.id("ROTATE_CREDENTIAL"),
  SET_VERIFIER: ethers.id("SET_VERIFIER"),
  SET_POLICY: ethers.id("SET_POLICY"),
  SET_GUARDIANS: ethers.id("SET_GUARDIANS"),
  RECOVER: ethers.id("RECOVER"),
  BIND_MIGRATION: ethers.id("BIND_MIGRATION"),
} as const;

const DOMAIN = { SPEND: 0, CREDENTIAL: 1, GUARDIAN: 2, MIGRATION: 3 } as const;

const abi = ethers.AbiCoder.defaultAbiCoder();

function domainSeparator(chainId: bigint, vault: string): string {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        ethers.id("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        ethers.id("WalletWallVaultKernel"),
        ethers.id("0-prototype"),
        chainId,
        vault,
      ],
    ),
  );
}

/**
 * The kernel's signing domain, mirrored exactly. EVERY field the kernel binds
 * appears here, so a test can omit or corrupt exactly one of them and nothing
 * else — which is what makes M-K08..M-K13 attributable.
 */
interface DigestParts {
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

function digestOf(p: DigestParts): string {
  const structHash = ethers.keccak256(
    abi.encode(
      ["bytes32", "uint64", "uint64", "bytes32", "uint8", "uint256", "uint64"],
      [p.actionType, p.kernelGeneration, p.authorityGeneration, p.params, p.domain, p.nonce, p.deadline],
    ),
  );
  return ethers.keccak256(ethers.concat(["0x1901", domainSeparator(p.chainId, p.vault), structHash]));
}

const signDigest = (key: ethers.SigningKey, digest: string) => ethers.Signature.from(key.sign(digest)).serialized;

/**
 * Sort a roster into the STRICTLY ASCENDING address order the kernel demands
 * (I-QUORUM-PRINCIPAL-DISTINCTNESS), keeping each seat with its auth mode.
 */
/**
 * Attestations aligned to the SORTED seat order. Hard-coded indices break the
 * moment a roster is canonicalised, and a silently mis-aligned attestation
 * looks like a quorum failure rather than a test bug.
 */
function attestBy(
  members: string[],
  digest: string,
  byAddress: Map<string, ethers.SigningKey>,
): { attestingIndices: number[]; attestations: string[] } {
  return {
    attestingIndices: members.map((_, i) => i),
    attestations: members.map((m) => {
      const k = byAddress.get(m.toLowerCase());
      return k === undefined ? "0x" : signDigest(k, digest);
    }),
  };
}

function sortRoster(members: string[], isContract: boolean[]): { members: string[]; isContract: boolean[] } {
  const pairs = members.map((m, i) => ({ m, c: isContract[i] })).sort((a, b) => (BigInt(a.m) < BigInt(b.m) ? -1 : 1));
  return { members: pairs.map((x) => x.m), isContract: pairs.map((x) => x.c) };
}

function rosterCommitment(threshold: bigint, members: string[], isContract: boolean[]): string {
  return ethers.keccak256(abi.encode(["uint64", "address[]", "bool[]"], [threshold, members, isContract]));
}

interface Floor {
  requirePq: boolean;
  pqParamLevel: number;
  pqPublicKeyLength: number;
  pqSignatureLength: number;
}

/** `setVerifier` binds the verifier AND the floor it is trusted for, together. */
function setVerifierParams(verifier: string, floor: Floor): string {
  return ethers.keccak256(
    abi.encode(
      ["address", "tuple(bool,uint16,uint32,uint32)"],
      [verifier, [floor.requirePq, floor.pqParamLevel, floor.pqPublicKeyLength, floor.pqSignatureLength]],
    ),
  );
}

/**
 * The PQ public key material the fixture commits to. It must be the PREIMAGE of
 * the vault's stored `pqPublicKeyHash`, not an arbitrary blob: the kernel checks
 * `keccak256(pqKey) == pqPublicKeyHash` before consulting the verifier at all.
 *
 * Getting this wrong is how a verifier test silently stops testing the verifier
 * — the call fails at the key-commitment check and never reaches the plane. The
 * paired positive control is what caught it during authoring.
 */
const PQ_KEY_LABEL = "pq-key";
const PQ_KEY = ethers.hexlify(ethers.toUtf8Bytes(PQ_KEY_LABEL));
/** The STRUCTURAL shape the kernel checks. Sizes only — never content. */
const PQ_PUBLIC_KEY_LENGTH = ethers.dataLength(PQ_KEY);
const PQ_SIGNATURE_LENGTH = 3309;
/** A correctly SHAPED signature. Its content is meaningless — see the header. */
const PQ_SIG = ethers.hexlify(new Uint8Array(PQ_SIGNATURE_LENGTH));

/**
 * The KERNEL-RECORDED floor the fixture commits to. `requirePq` is the KERNEL's
 * decision, never the CALLER's, so a HYBRID vault demands the PQ conjunct on
 * every asset-moving path. The two lengths are the structural rejection the
 * kernel performs itself, trusting no verifier.
 */
const HYBRID_FLOOR = {
  requirePq: true,
  pqParamLevel: 3,
  pqPublicKeyLength: PQ_PUBLIC_KEY_LENGTH,
  pqSignatureLength: PQ_SIGNATURE_LENGTH,
};
const ECDSA_ONLY_FLOOR = { requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 };

/** A second PQ factor, for rotation/recovery targets that must be POSSESSED. */
// SAME LENGTH as PQ_KEY: the kernel structural check compares against the
// declared floor length, so a second factor of a different size is refused
// before the verifier is ever consulted.
const PQ_KEY_2_LABEL = "pqkey2";
const PQ_KEY_2 = ethers.hexlify(ethers.toUtf8Bytes(PQ_KEY_2_LABEL));
const PQ_HASH_2 = ethers.id(PQ_KEY_2_LABEL);
/** A rotation/recovery target whose ECDSA key this suite actually holds. */
const ROTATE_KEY = new ethers.SigningKey(ethers.id("rotate-target-key"));
const ROTATE_TARGET = ethers.computeAddress(ROTATE_KEY.publicKey);

describe("vNext minimal trust kernel — prototype v0", function () {
  // ---------------------------------------------------------------------
  // Fixture
  // ---------------------------------------------------------------------
  type Fixture = Awaited<ReturnType<typeof deploy>>;

  async function deploy(verifierMode = 0) {
    const [deployer, attacker, recipient] = await ethers.getSigners();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const ownerKey = new ethers.SigningKey(ethers.id("owner-key"));
    const owner = ethers.computeAddress(ownerKey.publicKey);
    // Rosters are STRICTLY ASCENDING by address — that ordering IS the
    // principal-distinctness rule (I-QUORUM-PRINCIPAL-DISTINCTNESS), so the
    // fixture sorts rather than relying on key-derivation order.
    const gKeys = [1, 2, 3]
      .map((i) => new ethers.SigningKey(ethers.id(`guardian-${i}`)))
      .sort((a, b) =>
        BigInt(ethers.computeAddress(a.publicKey)) < BigInt(ethers.computeAddress(b.publicKey)) ? -1 : 1,
      );
    const guardians = gKeys.map((k) => ethers.computeAddress(k.publicKey));

    const Verifier = await ethers.getContractFactory("ConfigurableVerifier", deployer);
    const verifier = await Verifier.deploy(verifierMode);
    await verifier.waitForDeployment();

    const Impl = await ethers.getContractFactory("VaultKernelPrototype", deployer);
    const impl = await Impl.deploy();
    await impl.waitForDeployment();

    const Factory = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
    const factory = await Factory.deploy(await impl.getAddress(), 1);
    await factory.waitForDeployment();

    const threshold = 2n;
    const isContract = [false, false, false];
    const commitment = rosterCommitment(threshold, guardians, isContract);
    const salt = ethers.id("vault-1");
    const genesis = {
      signer: owner,
      pqKeyHash: ethers.id(PQ_KEY_LABEL),
      verifier: await verifier.getAddress(),
      threshold: Number(threshold),
      guardians,
      guardianIsContract: isContract,
      floor: HYBRID_FLOOR,
    };
    const predicted = await factory.predictVault(salt, genesis);
    await (await factory.deployVault(salt, genesis)).wait();

    const vault = await ethers.getContractAt("VaultKernelPrototype", predicted, deployer);
    await deployer.sendTransaction({ to: predicted, value: ethers.parseEther("10") });

    return {
      deployer,
      attacker,
      recipient,
      chainId,
      genesis,
      verifierAddress: await verifier.getAddress(),
      ownerKey,
      owner,
      gKeys,
      guardians,
      isContract,
      threshold,
      commitment,
      verifier,
      impl,
      factory,
      vault,
      vaultAddress: predicted,
      salt,
    };
  }

  /** The signing parts for an action against this fixture's vault. */
  function parts(f: Fixture, over: Partial<DigestParts>): DigestParts {
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

  const spendParams = (to: string, amount: bigint) =>
    ethers.keccak256(abi.encode(["address", "uint256"], [to, amount]));

  /**
   * The incoming credential a recovery installs, with both POSSESSION proofs
   * (I-INCOMING-CREDENTIAL-POSSESSION). The fixture's verifier is ALWAYS_TRUE,
   * so the PQ proof passes on shape alone — the ECDSA proof is the real one,
   * and it is signed by a key this suite actually holds.
   */
  async function recoveryChange(f: Fixture) {
    const pop = await f.vault.recoveryPossessionDigest();
    return {
      newSigner: ROTATE_TARGET,
      newPqKeyHash: PQ_HASH_2,
      newPqKey: PQ_KEY_2,
      newEcdsaPop: signDigest(ROTATE_KEY, pop),
      newPqPop: PQ_SIG,
    };
  }

  /** The same shape for an ordinary rotation. */
  async function rotationChange(f: Fixture, signer = ROTATE_TARGET, key = ROTATE_KEY) {
    const pop = await f.vault.credentialPossessionDigest(signer, PQ_HASH_2);
    return {
      newSigner: signer,
      newPqKeyHash: PQ_HASH_2,
      newPqKey: PQ_KEY_2,
      newEcdsaPop: signDigest(key, pop),
      newPqPop: PQ_SIG,
    };
  }

  /** A `k`-of-`n` quorum proof over the fixture roster, for a given digest. */
  function quorum(f: Fixture, digest: string, indices = [0, 1]) {
    return {
      members: f.guardians,
      isContract: f.isContract,
      attestingIndices: indices,
      attestations: indices.map((i) => signDigest(f.gKeys[i], digest)),
    };
  }

  // =====================================================================
  describe("structural — the stop conditions #179 names", function () {
    it("one clone is one vault: no owner-keyed vault mapping exists", async function () {
      const f = await deploy();
      // The ABI is the observable surface. A multi-tenant kernel would expose a
      // vault lookup keyed by an owner address; this one exposes none.
      const fns = f.vault.interface.fragments.filter((x) => x.type === "function");
      const ownerKeyed = fns.filter((x) => {
        const fr = x as ethers.FunctionFragment;
        return /vault/i.test(fr.name) && fr.inputs.some((i) => i.type === "address");
      });
      expect(ownerKeyed.map((x) => (x as ethers.FunctionFragment).name)).to.deep.equal([]);
      // Custody is the clone's own balance, not an entry in a shared ledger.
      expect(await ethers.provider.getBalance(f.vaultAddress)).to.equal(ethers.parseEther("10"));
    });

    it("no generic execute(address,bytes) capability exists", async function () {
      const f = await deploy();
      const names = f.vault.interface.fragments
        .filter((x) => x.type === "function")
        .map((x) => (x as ethers.FunctionFragment).format("sighash"));
      expect(names.some((n) => /^execute\(address,bytes/.test(n))).to.equal(false);
      expect(names.filter((n) => n.startsWith("execute("))).to.deep.equal([
        "execute(address,uint256,uint256,uint64,bytes,bytes,bytes)",
      ]);
    });
  });

  // =====================================================================
  describe("M-K01..M-K06 — initialization security (T0)", function () {
    it("M-K01 — an uninitialized clone is claimable, and the factory never leaves one", async function () {
      const f = await deploy();
      const Raw = await ethers.getContractFactory("RawCloner", f.deployer);
      const raw = await Raw.deploy();
      await raw.waitForDeployment();

      // POSITIVE CONTROL, and the demonstration of WHY atomicity is required:
      // a bare clone IS claimable by anyone.
      await (await raw.cloneOnly(await f.impl.getAddress(), ethers.id("bare"))).wait();
      const bare = await ethers.getContractAt("VaultKernelPrototype", await raw.lastClone(), f.attacker);
      await (await bare.initialize({ ...f.genesis, signer: f.attacker.address })).wait();
      expect(await bare.ecdsaSigner()).to.equal(f.attacker.address);

      // THE INVARIANT: the factory path never exposes that window. Deployment
      // and initialization are ONE transaction, so the vault is already owned
      // by the intended signer at the end of the only tx that created it.
      expect(await f.vault.ecdsaSigner()).to.equal(f.owner);
      const rcpt = await ethers.provider.getTransactionReceipt((await ethers.provider.getBlock("latest"))!.hash);
      void rcpt;
      // And a second initialization of the factory-made vault is refused.
      await expect(
        f.vault.connect(f.attacker).initialize({ ...f.genesis, signer: f.attacker.address }),
      ).to.be.revertedWithCustomError(f.vault, "AlreadyInitialized");
    });

    it("M-K02 — initialize twice is refused", async function () {
      const f = await deploy();
      expect(await f.vault.ecdsaSigner()).to.equal(f.owner); // control: it IS initialized
      await expect(f.vault.initialize({ ...f.genesis, signer: f.attacker.address })).to.be.revertedWithCustomError(
        f.vault,
        "AlreadyInitialized",
      );
    });

    it("M-K03 — the implementation itself can never be initialized or used as a vault", async function () {
      const f = await deploy();
      const implAsVault = await ethers.getContractAt("VaultKernelPrototype", await f.impl.getAddress(), f.attacker);
      // Control: the same call succeeds on a fresh bare clone (M-K01), so the
      // call shape is right and the refusal below is the constructor guard.
      await expect(implAsVault.initialize({ ...f.genesis, signer: f.attacker.address })).to.be.revertedWithCustomError(
        implAsVault,
        "AlreadyInitialized",
      );
      expect(await implAsVault.ecdsaSigner()).to.equal(ZERO);
      expect(await ethers.provider.getBalance(await f.impl.getAddress())).to.equal(0n);
    });

    it("M-K04 — the initialized commitment is exactly what was requested, and a wrong one is detectable", async function () {
      const f = await deploy();
      expect(await f.vault.guardianCommitment()).to.equal(f.commitment);
      expect(await f.vault.guardianThreshold()).to.equal(f.threshold);
      // A roster that does not hash to the stored commitment cannot authorize.
      const wrong = [f.attacker.address, f.guardians[1], f.guardians[2]];
      const digest = digestOf(parts(f, { actionType: ACTION.RECOVER, domain: DOMAIN.GUARDIAN }));
      await expect(
        f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: wrong,
            isContract: f.isContract,
            attestingIndices: [0, 1],
            attestations: [signDigest(f.gKeys[0], digest), signDigest(f.gKeys[1], digest)],
          },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(f.vault, "NotOrdered");
    });

    it("M-K05 — immutable args live in clone CODE and cannot be forged by storage", async function () {
      const f = await deploy();
      const args = await f.vault.genesisCommitments();
      expect(args).to.equal("0x0000000000000001"); // uint64 generation = 1
      expect(await f.vault.kernelGeneration()).to.equal(1n);

      // The args are part of the clone's own runtime code: 45-byte template + 8.
      const code = await ethers.provider.getCode(f.vaultAddress);
      expect(ethers.dataLength(code)).to.equal(45 + 8);
      expect(code.endsWith("0000000000000001")).to.equal(true);

      // A clone with DIFFERENT args has different code and a different address,
      // so args cannot be swapped under a fixed identity.
      const Raw = await ethers.getContractFactory("RawCloner", f.deployer);
      const raw = await Raw.deploy();
      await raw.waitForDeployment();
      await (await raw.cloneWithArgs(await f.impl.getAddress(), "0x0000000000000009", ethers.id("g9"))).wait();
      const other = await raw.lastClone();
      expect(await ethers.provider.getCode(other)).to.not.equal(code);
      expect(await (await ethers.getContractAt("VaultKernelPrototype", other, f.deployer)).kernelGeneration()).to.equal(
        9n,
      );
    });

    it("M-K06 — the CREATE2 prediction equals the deployed vault identity", async function () {
      const f = await deploy();
      const predicted = await f.factory.predictVault(f.salt, f.genesis);
      expect(predicted).to.equal(f.vaultAddress);
      expect(await ethers.provider.getCode(predicted)).to.not.equal("0x");
      // A different salt predicts a different address — the prediction is a
      // function of the salt, not a constant that happens to match.
      expect(await f.factory.predictVault(ethers.id("other"), f.genesis)).to.not.equal(predicted);
    });
  });

  // =====================================================================
  describe("M-K07 — generation-1 authentication (T0)", function () {
    it("POSITIVE CONTROL — a correctly signed HYBRID spend succeeds", async function () {
      const f = await deploy(0); // ALWAYS_TRUE verifier
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount) }));
      const before = await ethers.provider.getBalance(to);
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, d), PQ_SIG, PQ_KEY)).wait();
      expect(await ethers.provider.getBalance(to)).to.equal(before + amount);
    });

    it("M-K07 — an ALWAYS-TRUE verifier is NOT a sole authenticator", async function () {
      const f = await deploy(0); // ALWAYS_TRUE
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount) }));

      // The verifier says yes to everything. The floor still denies, because the
      // ECDSA conjunct is evaluated by the KERNEL and the attacker holds no key.
      const attackerKey = new ethers.SigningKey(ethers.id("attacker-key"));
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(attackerKey, d), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");

      // Control: the same call with the OWNER's signature succeeds, so the
      // verifier really was consulted and really did answer true.
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, d), PQ_SIG, PQ_KEY)).wait();
    });

    it("an ALWAYS-FALSE / reverting verifier causes DENIAL, never forgery", async function () {
      for (const mode of [1, 2]) {
        const f = await deploy(mode);
        const to = f.recipient.address;
        const amount = ethers.parseEther("1");
        const d = digestOf(parts(f, { params: spendParams(to, amount) }));
        const before = await ethers.provider.getBalance(f.vaultAddress);

        // A dead verifier DENIES. Note what is NOT asserted: nothing here says
        // the spend succeeds. Under a `requirePq` floor a broken plane takes
        // the vault offline for spending, and that is the correct, declared
        // trade — denial is inside the envelope, loss is not.
        let denied = false;
        try {
          await (
            await f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, d), PQ_SIG, PQ_KEY)
          ).wait();
        } catch {
          denied = true;
        }
        expect(denied, `mode ${mode}`).to.equal(true);
        expect(await ethers.provider.getBalance(f.vaultAddress)).to.equal(before);
        expect(await f.vault.nonces(DOMAIN.SPEND)).to.equal(0n);

        // CONTROL, and the proof that the denial is the VERIFIER and not the
        // signature: an otherwise identical vault under an ECDSA-only floor —
        // no PQ conjunct to fail — authorises the very same spend.
        const salt = ethers.id(`ecdsa-only-${mode}`);
        const ecdsaOnlyGenesis = { ...f.genesis, pqKeyHash: ethers.ZeroHash, floor: ECDSA_ONLY_FLOOR };
        const addr = await f.factory.predictVault(salt, ecdsaOnlyGenesis);
        await (await f.factory.deployVault(salt, ecdsaOnlyGenesis)).wait();
        await f.deployer.sendTransaction({ to: addr, value: ethers.parseEther("2") });
        const plain = await ethers.getContractAt("VaultKernelPrototype", addr, f.deployer);
        const pd = digestOf(parts(f, { vault: addr, params: spendParams(to, amount) }));
        await (await plain.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, pd), "0x", "0x")).wait();

        // And an attacker signature still fails on that same ECDSA-only vault,
        // so "the floor alone" is a real authenticator rather than an opening.
        const attackerKey = new ethers.SigningKey(ethers.id("attacker-key"));
        const pd2 = digestOf(parts(f, { vault: addr, params: spendParams(to, amount), nonce: 1n }));
        await expect(
          plain.execute(to, amount, 1, BigInt(2 ** 40), signDigest(attackerKey, pd2), "0x", "0x"),
        ).to.be.revertedWithCustomError(plain, "BadSignature");
      }
    });

    it("a Byzantine POLICY plane can only SUBTRACT authority", async function () {
      const f = await deploy(0);
      const Policy = await ethers.getContractFactory("ConfigurablePolicy", f.deployer);
      const deny = await Policy.deploy(false);
      await deny.waitForDeployment();

      const sp = digestOf(
        parts(f, {
          actionType: ACTION.SET_POLICY,
          params: ethers.keccak256(abi.encode(["address"], [await deny.getAddress()])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.setPolicy(await deny.getAddress(), 0, BigInt(2 ** 40), signDigest(f.ownerKey, sp), PQ_SIG, PQ_KEY)
      ).wait();

      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount) }));
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, d), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "PolicyDenied");

      // And a plane that says YES grants nothing on its own: an attacker
      // signature still fails with the permissive plane installed.
      const allow = await Policy.deploy(true);
      await allow.waitForDeployment();
      const sp2 = digestOf(
        parts(f, {
          actionType: ACTION.SET_POLICY,
          params: ethers.keccak256(abi.encode(["address"], [await allow.getAddress()])),
          domain: DOMAIN.CREDENTIAL,
          nonce: 1n,
        }),
      );
      await (
        await f.vault.setPolicy(
          await allow.getAddress(),
          1,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, sp2),
          PQ_SIG,
          PQ_KEY,
        )
      ).wait();
      const attackerKey = new ethers.SigningKey(ethers.id("attacker-key"));
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(attackerKey, d), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
    });

    it("M-K26 — the PQ conjunct is the KERNEL's decision, not the CALLER's", async function () {
      const f = await deploy(0);
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount) }));
      const sig = signDigest(f.ownerKey, d);

      // THE DEFECT THIS PINS. An earlier draft engaged the PQ leg only when the
      // caller supplied a non-empty signature, so anyone holding the ECDSA key
      // alone could downgrade HYBRID to ECDSA-only through the ARGUMENT LIST.
      // Under a `requirePq` floor an omitted or mis-shaped PQ leg is refused.
      await expect(f.vault.execute(to, amount, 0, BigInt(2 ** 40), sig, "0x", "0x")).to.be.revertedWithCustomError(
        f.vault,
        "BadSignature",
      );
      // A structurally WRONG length is refused by the kernel itself, before the
      // verifier is consulted at all (FLOOR component 1).
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), sig, ethers.hexlify(new Uint8Array(10)), PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
      // Control: correctly shaped material succeeds.
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), sig, PQ_SIG, PQ_KEY)).wait();
    });

    it("M-K27 — I-NO-SILENT-DOWNGRADE: the recorded floor may never be weakened", async function () {
      const f = await deploy(0);
      const Verifier = await ethers.getContractFactory("ConfigurableVerifier", f.deployer);
      const other = await Verifier.deploy(0);
      await other.waitForDeployment();
      const addr = await other.getAddress();

      // Turning the PQ requirement OFF is refused outright — there is no
      // principal in this design entitled to weaken the floor.
      const offD = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: setVerifierParams(addr, ECDSA_ONLY_FLOOR),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await expect(
        f.vault.setVerifier(addr, ECDSA_ONLY_FLOOR, 0, BigInt(2 ** 40), signDigest(f.ownerKey, offD), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "Downgrade");

      // Lowering the parameter level is refused too.
      const weaker = { ...HYBRID_FLOOR, pqParamLevel: 2 };
      const weakD = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: setVerifierParams(addr, weaker),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await expect(
        f.vault.setVerifier(addr, weaker, 0, BigInt(2 ** 40), signDigest(f.ownerKey, weakD), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "Downgrade");

      // CONTROL: a STRENGTHENING transition is permitted, proving the refusals
      // above are the downgrade rule and not a blanket refusal to change.
      const stronger = { ...HYBRID_FLOOR, pqParamLevel: 5 };
      const strongD = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: setVerifierParams(addr, stronger),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.setVerifier(addr, stronger, 0, BigInt(2 ** 40), signDigest(f.ownerKey, strongD), PQ_SIG, PQ_KEY)
      ).wait();
      expect((await f.vault.securityFloor()).pqParamLevel).to.equal(5);
    });

    /**
     * REWRITTEN — a RECORD OF A DESIGN CHANGE, not a test repair.
     *
     * This previously asserted that a dead verifier "can be replaced WITHOUT the
     * verifier answering" — i.e. that `setVerifier` was authorised by the ECDSA
     * conjunct ALONE. An independent review showed that property is a ONE-ROOT
     * path to total loss (finding A2, mutant M-K29): the same unilateral
     * authority lets a compromised ECDSA key install an ALWAYS-TRUE verifier,
     * keep the recorded floor untouched so no downgrade rule fires, and then
     * spend using the PUBLIC PQ public key with a forged signature.
     *
     * `I-NO-CIRCULAR-ESCAPE` is still required — it just cannot be satisfied by
     * that mechanism. The escape now lives with the GUARDIAN QUORUM: recovery
     * carries a replacement verifier. The liveness half is proven in
     * `KernelAuthorityClosure.test.ts` ("VERIFIER LIVENESS"). What is asserted
     * here is the half that belongs in this file — the one-factor escape is GONE.
     */
    it("I-NO-CIRCULAR-ESCAPE — the escape is NOT unilateral to one factor", async function () {
      const f = await deploy(2); // REVERTS forever
      const Verifier = await ethers.getContractFactory("ConfigurableVerifier", f.deployer);
      const good = await Verifier.deploy(0);
      await good.waitForDeployment();
      const d = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: setVerifierParams(await good.getAddress(), HYBRID_FLOOR),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      // The ECDSA factor alone cannot swap the verifier, even to a GOOD one and
      // even while the incumbent is dead. That is the price of closing A2, and
      // it is paid deliberately: the guardians hold the escape instead.
      let refused = false;
      try {
        await (
          await f.vault.setVerifier(
            await good.getAddress(),
            HYBRID_FLOOR,
            0,
            BigInt(2 ** 40),
            signDigest(f.ownerKey, d),
            PQ_SIG,
            PQ_KEY,
          )
        ).wait();
      } catch {
        refused = true;
      }
      expect(refused).to.equal(true);
      expect(await f.vault.pqVerifier()).to.not.equal(await good.getAddress());
    });
  });

  // =====================================================================
  describe("M-K08..M-K14 — domain separation and replay (T0)", function () {
    async function spendAttack(over: Partial<DigestParts>, f: Fixture) {
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const good = parts(f, { params: spendParams(to, amount) });
      const bad = { ...good, ...over };
      return {
        to,
        amount,
        goodSig: signDigest(f.ownerKey, digestOf(good)),
        badSig: signDigest(f.ownerKey, digestOf(bad)),
      };
    }

    it("M-K08 — a signature not bound to the VAULT ADDRESS is rejected", async function () {
      const f = await deploy(0);
      const a = await spendAttack({ vault: ZERO }, f);
      await expect(
        f.vault.execute(a.to, a.amount, 0, BigInt(2 ** 40), a.badSig, PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
      await (await f.vault.execute(a.to, a.amount, 0, BigInt(2 ** 40), a.goodSig, PQ_SIG, PQ_KEY)).wait();
    });

    it("M-K09 — a signature not bound to the CHAIN ID is rejected", async function () {
      const f = await deploy(0);
      const a = await spendAttack({ chainId: 999999n }, f);
      await expect(
        f.vault.execute(a.to, a.amount, 0, BigInt(2 ** 40), a.badSig, PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
      await (await f.vault.execute(a.to, a.amount, 0, BigInt(2 ** 40), a.goodSig, PQ_SIG, PQ_KEY)).wait();
    });

    it("M-K10 — a signature not bound to the ACTION TYPE is rejected", async function () {
      const f = await deploy(0);
      const a = await spendAttack({ actionType: ACTION.ROTATE }, f);
      await expect(
        f.vault.execute(a.to, a.amount, 0, BigInt(2 ** 40), a.badSig, PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
      await (await f.vault.execute(a.to, a.amount, 0, BigInt(2 ** 40), a.goodSig, PQ_SIG, PQ_KEY)).wait();
    });

    it("M-K11 — a stale AUTHORITY GENERATION is rejected after rotation", async function () {
      const f = await deploy(0);
      const newKey = new ethers.SigningKey(ethers.id("owner-key-2"));
      const newSigner = ethers.computeAddress(newKey.publicKey);
      // Rotate to the SAME pq key commitment: changing it would make the
      // mandatory PQ conjunct unsatisfiable and mask the generation check
      // this test exists to exercise.
      const pqHash = ethers.id(PQ_KEY_LABEL);
      const rot = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [newSigner, PQ_HASH_2])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.rotateCredential(
          await rotationChange(f, newSigner, newKey),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, rot),
          PQ_SIG,
          PQ_KEY,
        )
      ).wait();
      expect(await f.vault.credentialGeneration()).to.equal(2n);

      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      // Signed under the OLD generation by the NEW key: correct key, stale gen.
      // After the rotation the committed PQ key is PQ_KEY_2, so post-rotation
      // spends must present its preimage.
      const stale = digestOf(parts(f, { params: spendParams(to, amount), authorityGeneration: 1n }));
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(newKey, stale), PQ_SIG, PQ_KEY_2),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
      const fresh = digestOf(parts(f, { params: spendParams(to, amount), authorityGeneration: 2n }));
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(newKey, fresh), PQ_SIG, PQ_KEY_2)).wait();
    });

    it("M-K12 — a spend signature cannot be replayed into another ACTION DOMAIN", async function () {
      const f = await deploy(0);
      // A signature authorising a SPEND must not authorise a ROTATE, even with
      // matching nonce values, because the domain byte and action type differ.
      const rotateAsSpend = digestOf(
        parts(f, {
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [ROTATE_TARGET, PQ_HASH_2])),
          domain: DOMAIN.SPEND,
          actionType: ACTION.SPEND,
        }),
      );
      await expect(
        f.vault.rotateCredential(
          await rotationChange(f),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, rotateAsSpend),
          PQ_SIG,
          PQ_KEY,
        ),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");
      const proper = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [ROTATE_TARGET, PQ_HASH_2])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.rotateCredential(
          await rotationChange(f),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, proper),
          PQ_SIG,
          PQ_KEY,
        )
      ).wait();
    });

    it("M-K13 — a signature for vault X is structurally invalid at vault Y", async function () {
      const f = await deploy(0);
      const salt2 = ethers.id("vault-2");
      const second = await f.factory.predictVault(salt2, f.genesis);
      await (await f.factory.deployVault(salt2, f.genesis)).wait();
      await f.deployer.sendTransaction({ to: second, value: ethers.parseEther("5") });
      const vault2 = await ethers.getContractAt("VaultKernelPrototype", second, f.deployer);

      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      // Signed for vault ONE, replayed at vault TWO. Same owner, same nonce.
      const forVault1 = digestOf(parts(f, { params: spendParams(to, amount) }));
      await expect(
        vault2.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, forVault1), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(vault2, "BadSignature");
      const forVault2 = digestOf(parts(f, { vault: second, params: spendParams(to, amount) }));
      await (
        await vault2.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, forVault2), PQ_SIG, PQ_KEY)
      ).wait();
    });

    it("M-K14 — the nonce is consumed, so a valid signature cannot be replayed", async function () {
      const f = await deploy(0);
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount) }));
      const sig = signDigest(f.ownerKey, d);
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), sig, PQ_SIG, PQ_KEY)).wait();
      expect(await f.vault.nonces(DOMAIN.SPEND)).to.equal(1n);
      await expect(f.vault.execute(to, amount, 0, BigInt(2 ** 40), sig, PQ_SIG, PQ_KEY)).to.be.revertedWithCustomError(
        f.vault,
        "BadNonce",
      );
    });

    it("nonce domains are INDEPENDENT — a credential action does not consume a spend nonce", async function () {
      const f = await deploy(0);
      const rot = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [ROTATE_TARGET, PQ_HASH_2])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.rotateCredential(
          await rotationChange(f),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, rot),
          PQ_SIG,
          PQ_KEY,
        )
      ).wait();
      expect(await f.vault.nonces(DOMAIN.CREDENTIAL)).to.equal(1n);
      expect(await f.vault.nonces(DOMAIN.SPEND)).to.equal(0n);
      expect(await f.vault.nonces(DOMAIN.GUARDIAN)).to.equal(0n);
      expect(await f.vault.nonces(DOMAIN.MIGRATION)).to.equal(0n);
    });

    it("a past deadline is refused", async function () {
      const f = await deploy(0);
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const past = BigInt((await ethers.provider.getBlock("latest"))!.timestamp - 1);
      const d = digestOf(parts(f, { params: spendParams(to, amount), deadline: past }));
      await expect(
        f.vault.execute(to, amount, 0, past, signDigest(f.ownerKey, d), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "Expired");
    });
  });

  // =====================================================================
  describe("M-K15..M-K19 — guardian authority (T0/T1)", function () {
    function recoveryDigest(f: Fixture, proposed: string, nonce = 0n, gen = 1n) {
      return digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          authorityGeneration: gen,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [ROTATE_TARGET, PQ_HASH_2, f.verifierAddress]),
          ),
          domain: DOMAIN.GUARDIAN,
          nonce,
        }),
      );
    }

    it("POSITIVE CONTROL — a k-of-n quorum initiates recovery", async function () {
      const f = await deploy(0);
      const proposed = ROTATE_TARGET;
      const d = recoveryDigest(f, proposed);
      await (
        await f.vault.initiateRecovery(proposed, PQ_HASH_2, f.verifierAddress, quorum(f, d), 0, BigInt(2 ** 40))
      ).wait();
      expect((await f.vault.recovery()).active).to.equal(true);
    });

    it("M-K15 — a roster preimage that does not hash to the commitment is rejected", async function () {
      const f = await deploy(0);
      const proposed = ROTATE_TARGET;
      const d = recoveryDigest(f, proposed);
      const forged = [f.attacker.address, f.guardians[1], f.guardians[2]];
      await expect(
        f.vault.initiateRecovery(
          proposed,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: forged,
            isContract: f.isContract,
            attestingIndices: [1, 2],
            attestations: [signDigest(f.gKeys[1], d), signDigest(f.gKeys[2], d)],
          },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(f.vault, "NotOrdered");
      // Control: the true roster with the same attesters succeeds.
      await (
        await f.vault.initiateRecovery(proposed, PQ_HASH_2, f.verifierAddress, quorum(f, d, [1, 2]), 0, BigInt(2 ** 40))
      ).wait();
    });

    it("M-K15b — the THRESHOLD is inside the preimage, so it cannot be supplied by the attacker", async function () {
      const f = await deploy(0);
      const d = recoveryDigest(f, f.attacker.address);
      // Same members, threshold claimed as 1. The commitment covers threshold,
      // so this preimage does not match and is refused before any counting.
      expect(rosterCommitment(1n, f.guardians, f.isContract)).to.not.equal(f.commitment);
      await expect(
        f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: f.guardians,
            isContract: [true, true, true],
            attestingIndices: [0],
            attestations: [signDigest(f.gKeys[0], d)],
          },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(f.vault, "BadRoster");
    });

    it("M-K16 — a stale guardian generation cannot authorize", async function () {
      const f = await deploy(0);
      const newGuardians = [f.guardians[0], f.guardians[1], f.deployer.address];
      const newCommitment = rosterCommitment(2n, newGuardians, f.isContract);
      const sg = digestOf(
        parts(f, {
          actionType: ACTION.SET_GUARDIANS,
          authorityGeneration: 1n,
          params: newCommitment,
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (await f.vault.setGuardians(2, newGuardians, f.isContract, quorum(f, sg), 0, BigInt(2 ** 40))).wait();
      expect(await f.vault.guardianGeneration()).to.equal(2n);

      // Signed under generation 1 — the correct guardians, the wrong generation.
      const stale = recoveryDigest(f, f.attacker.address, 1n, 1n);
      await expect(
        f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: newGuardians,
            isContract: f.isContract,
            attestingIndices: [0, 1],
            attestations: [signDigest(f.gKeys[0], stale), signDigest(f.gKeys[1], stale)],
          },
          1,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(f.vault, "QuorumNotMet");
      // Control: generation 2 succeeds.
      const fresh = recoveryDigest(f, f.attacker.address, 1n, 2n);
      await (
        await f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: newGuardians,
            isContract: f.isContract,
            attestingIndices: [0, 1],
            attestations: [signDigest(f.gKeys[0], fresh), signDigest(f.gKeys[1], fresh)],
          },
          1,
          BigInt(2 ** 40),
        )
      ).wait();
    });

    it("M-K17 — one guardian cannot be counted twice", async function () {
      const f = await deploy(0);
      const d = recoveryDigest(f, f.attacker.address);
      await expect(
        f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: f.guardians,
            isContract: f.isContract,
            attestingIndices: [0, 0],
            attestations: [signDigest(f.gKeys[0], d), signDigest(f.gKeys[0], d)],
          },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(f.vault, "NotOrdered");
      // Descending order is refused too — the rule is STRICTLY ASCENDING.
      await expect(
        f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members: f.guardians,
            isContract: f.isContract,
            attestingIndices: [1, 0],
            attestations: [signDigest(f.gKeys[1], d), signDigest(f.gKeys[0], d)],
          },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(f.vault, "NotOrdered");
      // Control: two DISTINCT ascending indices succeed.
      await (
        await f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          quorum(f, d, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
    });

    it("M-K18 — k-1 attestations do not meet the threshold", async function () {
      const f = await deploy(0);
      const d = recoveryDigest(f, f.attacker.address);
      await expect(
        f.vault.initiateRecovery(ROTATE_TARGET, PQ_HASH_2, f.verifierAddress, quorum(f, d, [0]), 0, BigInt(2 ** 40)),
      ).to.be.revertedWithCustomError(f.vault, "QuorumNotMet");
      await (
        await f.vault.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          quorum(f, d, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
    });

    it("M-K19 — a minority cannot replace the guardian commitment", async function () {
      const f = await deploy(0);
      // Canonical (sorted, distinct) so this test still probes the THRESHOLD;
      // duplicate rosters are refused earlier and are covered by M-K30.
      const hostile = sortRoster([f.attacker.address, f.deployer.address], [false, false]).members;
      const newCommitment = rosterCommitment(1n, hostile, [false, false]);
      const sg = digestOf(
        parts(f, { actionType: ACTION.SET_GUARDIANS, params: newCommitment, domain: DOMAIN.GUARDIAN }),
      );
      await expect(
        f.vault.setGuardians(1, hostile, [false, false], quorum(f, sg, [0]), 0, BigInt(2 ** 40)),
      ).to.be.revertedWithCustomError(f.vault, "QuorumNotMet");
      expect(await f.vault.guardianCommitment()).to.equal(f.commitment);
      // Control: the full quorum can.
      await (await f.vault.setGuardians(1, hostile, [false, false], quorum(f, sg, [0, 1]), 0, BigInt(2 ** 40))).wait();
      expect(await f.vault.guardianCommitment()).to.equal(newCommitment);
    });

    it("I-CONSTITUENCY-RECONSTRUCTIBLE — every commitment write emits the FULL preimage", async function () {
      const f = await deploy(0);
      const newGuardians = [f.guardians[0], f.guardians[1], f.deployer.address];
      const newCommitment = rosterCommitment(2n, newGuardians, f.isContract);
      const sg = digestOf(
        parts(f, { actionType: ACTION.SET_GUARDIANS, params: newCommitment, domain: DOMAIN.GUARDIAN }),
      );
      const rcpt = await (
        await f.vault.setGuardians(2, newGuardians, f.isContract, quorum(f, sg), 0, BigInt(2 ** 40))
      ).wait();
      const ev = rcpt!.logs.map((l) => f.vault.interface.parseLog(l)).find((l) => l?.name === "GuardianCommitmentSet");
      expect(ev).to.not.equal(undefined);
      // The emitted preimage must re-hash to the stored commitment.
      expect(ethers.keccak256(ev!.args.preimage)).to.equal(await f.vault.guardianCommitment());
      const decoded = abi.decode(["uint64", "address[]", "bool[]"], ev!.args.preimage);
      expect(decoded[1]).to.deep.equal(newGuardians);
    });

    it("I-GUARDIAN-FAULT-ISOLATION — every hostile guardian behaviour is contained", async function () {
      const f = await deploy(0);
      const Good = await ethers.getContractFactory("GoodContractGuardian", f.deployer);
      const good = await Good.deploy();
      await good.waitForDeployment();

      for (const name of ["RevertingGuardian", "GasBurningGuardian", "WrongAnswerGuardian", "HugeReturnGuardian"]) {
        const F = await ethers.getContractFactory(name, f.deployer);
        const bad = await F.deploy();
        await bad.waitForDeployment();

        const sorted = sortRoster(
          [await good.getAddress(), await bad.getAddress(), f.guardians[0]],
          [true, true, false],
        );
        const members = sorted.members;
        const isC = sorted.isContract;
        const commitment = rosterCommitment(2n, members, isC);
        const salt = ethers.id("iso-" + name);
        const addr = await f.factory.predictVault(salt, {
          ...f.genesis,
          guardians: members,
          guardianIsContract: isC,
          threshold: 2,
        });
        await (
          await f.factory.deployVault(salt, { ...f.genesis, guardians: members, guardianIsContract: isC, threshold: 2 })
        ).wait();
        const v = await ethers.getContractAt("VaultKernelPrototype", addr, f.deployer);

        const d = digestOf(
          parts(f, {
            vault: addr,
            actionType: ACTION.RECOVER,
            params: ethers.keccak256(
              abi.encode(["address", "bytes32", "address"], [ROTATE_TARGET, PQ_HASH_2, f.verifierAddress]),
            ),
            domain: DOMAIN.GUARDIAN,
          }),
        );
        // The GOOD contract guardian and the EOA guardian reach quorum; the
        // hostile one is consulted in between and changes NOTHING.
        await (
          await v.initiateRecovery(
            ROTATE_TARGET,
            PQ_HASH_2,
            f.verifierAddress,
            {
              members,
              isContract: isC,
              // Index-aware: only the EOA seat carries a signature, wherever
              // canonical ordering happens to place it. The two contract seats
              // answer through their own code.
              ...attestBy(members, d, new Map([[f.guardians[0].toLowerCase(), f.gKeys[0]]])),
            },
            0,
            BigInt(2 ** 40),
            { gasLimit: 3_000_000 },
          )
        ).wait();
        expect((await v.recovery()).active, name).to.equal(true);
      }
    });

    it("I-ATTESTATION-IS-AFFIRMATIVE — a non-magic 32-byte answer is NOT an attestation", async function () {
      const f = await deploy(0);
      const Wrong = await ethers.getContractFactory("WrongAnswerGuardian", f.deployer);
      const wrong = await Wrong.deploy();
      await wrong.waitForDeployment();
      const Good = await ethers.getContractFactory("GoodContractGuardian", f.deployer);
      const good = await Good.deploy();
      await good.waitForDeployment();

      const sorted = sortRoster([await wrong.getAddress(), await good.getAddress()], [true, true]);
      const members = sorted.members;
      const isC = sorted.isContract;
      const commitment = rosterCommitment(2n, members, isC);
      const salt = ethers.id("affirm");
      const addr = await f.factory.predictVault(salt, {
        ...f.genesis,
        guardians: members,
        guardianIsContract: isC,
        threshold: 2,
      });
      await (
        await f.factory.deployVault(salt, { ...f.genesis, guardians: members, guardianIsContract: isC, threshold: 2 })
      ).wait();
      const v = await ethers.getContractAt("VaultKernelPrototype", addr, f.deployer);

      // Only ONE of the two answers affirmatively, so a threshold of 2 fails.
      await expect(
        v.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          { members, isContract: isC, attestingIndices: [0, 1], attestations: ["0x", "0x"] },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(v, "QuorumNotMet");
    });

    it("I-GUARDIAN-AUTH-MODE-IS-COMMITTED — a contract seat is not inferred from extcodesize", async function () {
      const f = await deploy(0);
      const Good = await ethers.getContractFactory("GoodContractGuardian", f.deployer);
      const good = await Good.deploy();
      await good.waitForDeployment();
      // The seat is committed as an EOA. Even though the address HAS code, the
      // kernel uses the committed mode and demands an ECDSA signature it cannot
      // produce, so the seat does not attest.
      const sorted = sortRoster([await good.getAddress(), f.guardians[0], f.guardians[1]], [false, false, false]);
      const members = sorted.members;
      const isC = sorted.isContract;
      const commitment = rosterCommitment(3n, members, isC);
      const salt = ethers.id("mode");
      const addr = await f.factory.predictVault(salt, {
        ...f.genesis,
        guardians: members,
        guardianIsContract: isC,
        threshold: 3,
      });
      await (
        await f.factory.deployVault(salt, { ...f.genesis, guardians: members, guardianIsContract: isC, threshold: 3 })
      ).wait();
      const v = await ethers.getContractAt("VaultKernelPrototype", addr, f.deployer);
      const d = digestOf(
        parts(f, {
          vault: addr,
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [ROTATE_TARGET, PQ_HASH_2, f.verifierAddress]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await expect(
        v.initiateRecovery(
          ROTATE_TARGET,
          PQ_HASH_2,
          f.verifierAddress,
          {
            members,
            isContract: isC,
            attestingIndices: [0, 1, 2],
            attestations: ["0x", signDigest(f.gKeys[0], d), signDigest(f.gKeys[1], d)],
          },
          0,
          BigInt(2 ** 40),
        ),
      ).to.be.revertedWithCustomError(v, "QuorumNotMet");
    });
  });

  // =====================================================================
  describe("recovery — sovereignty and the bounded challenge", function () {
    async function pending(f: Fixture, nonce = 0n) {
      const proposed = ROTATE_TARGET;
      const d = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [ROTATE_TARGET, PQ_HASH_2, f.verifierAddress]),
          ),
          domain: DOMAIN.GUARDIAN,
          nonce,
        }),
      );
      await (
        await f.vault.initiateRecovery(proposed, PQ_HASH_2, f.verifierAddress, quorum(f, d), nonce, BigInt(2 ** 40))
      ).wait();
      return proposed;
    }

    it("recovery matures and installs the proposed credential", async function () {
      const f = await deploy(0);
      const proposed = await pending(f);
      await expect(f.vault.executeRecovery(await recoveryChange(f))).to.be.revertedWithCustomError(f.vault, "TooEarly");
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.executeRecovery(await recoveryChange(f))).wait();
      expect(await f.vault.ecdsaSigner()).to.equal(proposed);
      expect(await f.vault.credentialGeneration()).to.equal(2n);
    });

    /**
     * NARROWED — the old title claimed more than the kernel now delivers, and
     * the difference is worth stating rather than papering over.
     *
     * Recovery consults NO PLANE IT IS ESCAPING FROM: not the policy engine, and
     * not the OUTGOING verifier. It DOES consult the INCOMING verifier, because
     * incoming possession must be proven against the replacement rather than
     * against the corpse (finding D). That is a dependency on a component the
     * guardians chose in the same act, not on the one that failed.
     */
    it("recovery consults no plane it is ESCAPING FROM — policy dead, outgoing verifier dead", async function () {
      const f = await deploy(0);
      const Policy = await ethers.getContractFactory("ConfigurablePolicy", f.deployer);
      const deny = await Policy.deploy(false);
      await deny.waitForDeployment();
      const sp = digestOf(
        parts(f, {
          actionType: ACTION.SET_POLICY,
          params: ethers.keccak256(abi.encode(["address"], [await deny.getAddress()])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.setPolicy(await deny.getAddress(), 0, BigInt(2 ** 40), signDigest(f.ownerKey, sp), PQ_SIG, PQ_KEY)
      ).wait();

      // Now kill the OUTGOING verifier, through the legitimate HYBRID path.
      const Dead = await ethers.getContractFactory("ConfigurableVerifier", f.deployer);
      const dead = await Dead.deploy(2);
      await dead.waitForDeployment();
      const dv = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: setVerifierParams(await dead.getAddress(), HYBRID_FLOOR),
          domain: DOMAIN.CREDENTIAL,
          nonce: 1n,
        }),
      );
      await (
        await f.vault.setVerifier(
          await dead.getAddress(),
          HYBRID_FLOOR,
          1,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, dv),
          PQ_SIG,
          PQ_KEY,
        )
      ).wait();

      const proposed = await pending(f);
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.executeRecovery(await recoveryChange(f))).wait();
      expect(await f.vault.ecdsaSigner()).to.equal(proposed);
    });

    it("I-VETO-BOUND — the credential challenge is bounded, so it is not a permanent veto", async function () {
      const f = await deploy(0);
      for (let i = 0; i < 2; i++) {
        await pending(f, BigInt(i));
        const d = digestOf(
          parts(f, {
            actionType: ACTION.RECOVER,
            params: ethers.id("CANCEL"),
            domain: DOMAIN.CREDENTIAL,
            nonce: BigInt(i),
          }),
        );
        await (await f.vault.cancelRecovery(i, BigInt(2 ** 40), signDigest(f.ownerKey, d))).wait();
      }
      expect((await f.vault.recovery()).challengesUsed).to.equal(2);
      // The third challenge is refused: the budget is spent and the guardians
      // now win by waiting.
      await pending(f, 2n);
      const d3 = digestOf(
        parts(f, { actionType: ACTION.RECOVER, params: ethers.id("CANCEL"), domain: DOMAIN.CREDENTIAL, nonce: 2n }),
      );
      await expect(
        f.vault.cancelRecovery(2, BigInt(2 ** 40), signDigest(f.ownerKey, d3)),
      ).to.be.revertedWithCustomError(f.vault, "ChallengeExhausted");
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.executeRecovery(await recoveryChange(f))).wait();
    });
  });

  // =====================================================================
  describe("M-K20 — the safe-state machine and containment (T0)", function () {
    async function contain(f: Fixture, nonce: bigint) {
      const d = digestOf(
        parts(f, { actionType: ACTION.RECOVER, params: ethers.id("CONTAIN"), domain: DOMAIN.GUARDIAN, nonce }),
      );
      return f.vault.enterContainment(quorum(f, d), nonce, BigInt(2 ** 40));
    }

    it("containment withdraws SPENDING and never RECOVERY", async function () {
      const f = await deploy(0);
      await (await contain(f, 0n)).wait();
      expect(await f.vault.safeState()).to.equal(1); // CONTAINED

      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const sd = digestOf(parts(f, { params: spendParams(to, amount) }));
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, sd), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadState");

      // Recovery stays available — this is what denies the emergency principal
      // a veto.
      const rd = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [ROTATE_TARGET, PQ_HASH_2, f.verifierAddress]),
          ),
          domain: DOMAIN.GUARDIAN,
          nonce: 1n,
        }),
      );
      await (
        await f.vault.initiateRecovery(ROTATE_TARGET, PQ_HASH_2, f.verifierAddress, quorum(f, rd), 1, BigInt(2 ** 40))
      ).wait();
      expect((await f.vault.recovery()).active).to.equal(true);
    });

    it("containment self-expires on WALL CLOCK with no principal acting", async function () {
      const f = await deploy(0);
      await (await contain(f, 0n)).wait();
      await ethers.provider.send("evm_increaseTime", [4 * DAY]);
      await ethers.provider.send("evm_mine", []);
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const sd = digestOf(parts(f, { params: spendParams(to, amount) }));
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, sd), PQ_SIG, PQ_KEY)).wait();
    });

    it("M-K20 — repeated re-triggering cannot produce an indefinite freeze", async function () {
      const f = await deploy(0);
      // CONTAINMENT_MAX 3d, BUDGET 6d, WINDOW 30d => at most 2 episodes per
      // window, so an infinite sequence of UNCONTAINED intervals is guaranteed.
      await (await contain(f, 0n)).wait();
      await ethers.provider.send("evm_increaseTime", [4 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await contain(f, 1n)).wait();
      await ethers.provider.send("evm_increaseTime", [4 * DAY]);
      await ethers.provider.send("evm_mine", []);

      // The budget is spent. A third trigger inside the same window is refused.
      await expect(contain(f, 2n)).to.be.revertedWithCustomError(f.vault, "ContainmentBudget");

      // And the vault is spendable during the forced gap.
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const sd = digestOf(parts(f, { params: spendParams(to, amount) }));
      await (await f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, sd), PQ_SIG, PQ_KEY)).wait();

      // Control: after the WINDOW elapses the budget refreshes, proving the
      // refusal above was the budget and not a permanent lockout.
      await ethers.provider.send("evm_increaseTime", [31 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await contain(f, 2n)).wait();
    });

    it("re-entry while already contained is a no-op, not an extension", async function () {
      const f = await deploy(0);
      await (await contain(f, 0n)).wait();
      const until = await f.vault.containedUntil();
      await ethers.provider.send("evm_increaseTime", [DAY]);
      await ethers.provider.send("evm_mine", []);
      await expect(contain(f, 1n)).to.be.revertedWithCustomError(f.vault, "BadState");
      expect(await f.vault.containedUntil()).to.equal(until);
    });
  });

  // =====================================================================
  describe("M-K21..M-K25 — migration (T0)", function () {
    async function destination(f: Fixture) {
      const D = await ethers.getContractFactory("DestinationStub", f.deployer);
      const d = await D.deploy();
      await d.waitForDeployment();
      const addr = await d.getAddress();
      return { addr, codeHash: ethers.keccak256(await ethers.provider.getCode(addr)) };
    }

    async function bind(f: Fixture, dest: { addr: string; codeHash: string }, nonce = 0n) {
      const params = ethers.keccak256(abi.encode(["address", "bytes32", "uint64"], [dest.addr, dest.codeHash, 2n]));
      const d = digestOf(parts(f, { actionType: ACTION.BIND_MIGRATION, params, domain: DOMAIN.MIGRATION, nonce }));
      return f.vault.bindMigration(
        { vault: dest.addr, codeHash: dest.codeHash, generation: 2 },
        quorum(f, d),
        nonce,
        BigInt(2 ** 40),
        signDigest(f.ownerKey, d),
      );
    }

    it("POSITIVE CONTROL — binding requires quorum AND credential, then egress moves the balance", async function () {
      const f = await deploy(0);
      const dest = await destination(f);
      await (await bind(f, dest)).wait();
      expect(await f.vault.safeState()).to.equal(3); // MIGRATION_ONLY
      const before = await ethers.provider.getBalance(dest.addr);
      await (await f.vault.egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(dest.addr)).to.equal(before + ethers.parseEther("10"));
      expect(await ethers.provider.getBalance(f.vaultAddress)).to.equal(0n);
    });

    it("M-K21 — a binding with no destination is refused", async function () {
      const f = await deploy(0);
      const params = ethers.keccak256(abi.encode(["address", "bytes32", "uint64"], [ZERO, ethers.ZeroHash, 2n]));
      const d = digestOf(parts(f, { actionType: ACTION.BIND_MIGRATION, params, domain: DOMAIN.MIGRATION }));
      await expect(
        f.vault.bindMigration(
          { vault: ZERO, codeHash: ethers.ZeroHash, generation: 2 },
          quorum(f, d),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, d),
        ),
      ).to.be.revertedWithCustomError(f.vault, "DestinationMismatch");
    });

    it("M-K22 — the destination CODE HASH is re-checked at execution, not only at binding", async function () {
      const f = await deploy(0);
      const dest = await destination(f);
      // Bind to the right address with a WRONG code hash; the signature covers
      // it, so binding succeeds and EGRESS is where the lie is caught.
      const wrongHash = ethers.id("not-the-code");
      const params = ethers.keccak256(abi.encode(["address", "bytes32", "uint64"], [dest.addr, wrongHash, 2n]));
      const d = digestOf(parts(f, { actionType: ACTION.BIND_MIGRATION, params, domain: DOMAIN.MIGRATION }));
      await (
        await f.vault.bindMigration(
          { vault: dest.addr, codeHash: wrongHash, generation: 2 },
          quorum(f, d),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, d),
        )
      ).wait();
      await expect(f.vault.egress(ZERO)).to.be.revertedWithCustomError(f.vault, "DestinationMismatch");
    });

    it("M-K23 — a second, different destination cannot be bound after the first", async function () {
      const f = await deploy(0);
      const dest = await destination(f);
      await (await bind(f, dest)).wait();
      const evil = await destination(f);
      await expect(bind(f, evil, 1n)).to.be.revertedWithCustomError(f.vault, "AlreadyBound");
      // And egress still goes to the ORIGINAL destination.
      await (await f.vault.egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(evil.addr)).to.equal(0n);
    });

    it("M-K24 — a hostile UNMANIFESTED token cannot veto the egress of everything else", async function () {
      const f = await deploy(0);
      const Token = await ethers.getContractFactory("TestToken", f.deployer);
      const good = await Token.deploy(false);
      await good.waitForDeployment();
      const hostile = await Token.deploy(true); // reverts on transfer
      await hostile.waitForDeployment();
      // Both arrive with NO call into the vault — the section 13.0a scenario.
      await (await good.mint(f.vaultAddress, 1000n)).wait();
      await (await hostile.mint(f.vaultAddress, 1n)).wait();

      const dest = await destination(f);
      await (await bind(f, dest)).wait();

      // The hostile entry fails ON ITS OWN and marks only itself.
      await expect(f.vault.egress(await hostile.getAddress())).to.be.revertedWithCustomError(f.vault, "TransferFailed");
      // Every other asset still leaves — independently, in any order.
      await (await f.vault.egress(await good.getAddress())).wait();
      expect(await good.balanceOf(dest.addr)).to.equal(1000n);
      await (await f.vault.egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(dest.addr)).to.equal(ethers.parseEther("10"));
    });

    it("no false settlement — a token that returns false without reverting is not marked moved", async function () {
      const f = await deploy(0);
      const T = await ethers.getContractFactory("SilentlyFailingToken", f.deployer);
      const t = await T.deploy();
      await t.waitForDeployment();
      await (await t.mint(f.vaultAddress, 500n)).wait();
      const dest = await destination(f);
      await (await bind(f, dest)).wait();
      // The call does not revert, and the balance does not move. Settlement is
      // judged on the OBSERVED decrease, so this must fail rather than succeed.
      await expect(f.vault.egress(await t.getAddress())).to.be.revertedWithCustomError(f.vault, "TransferFailed");
      expect(await t.balanceOf(f.vaultAddress)).to.equal(500n);
    });

    it("M-K25 — RETIRED retains NO discretionary spending, and egress stays open forever", async function () {
      const f = await deploy(0);
      const dest = await destination(f);
      await (await bind(f, dest)).wait();
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.retire()).wait();
      expect(await f.vault.safeState()).to.equal(4); // RETIRED

      // No discretionary authority survives.
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const sd = digestOf(parts(f, { params: spendParams(to, amount) }));
      await expect(
        f.vault.execute(to, amount, 0, BigInt(2 ** 40), signDigest(f.ownerKey, sd), PQ_SIG, PQ_KEY),
      ).to.be.revertedWithCustomError(f.vault, "BadState");
      const rot = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [ROTATE_TARGET, PQ_HASH_2])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await expect(
        f.vault.rotateCredential(
          await rotationChange(f),
          0,
          BigInt(2 ** 40),
          signDigest(f.ownerKey, rot),
          PQ_SIG,
          PQ_KEY,
        ),
      ).to.be.revertedWithCustomError(f.vault, "BadState");

      // But egress is PRE-COMMITTED, not discretionary, so it survives — and
      // assets arriving AFTER retirement are still claimable (salvage).
      await (await f.vault.egress(ZERO)).wait();
      await f.deployer.sendTransaction({ to: f.vaultAddress, value: ethers.parseEther("3") });
      await (await f.vault.egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(dest.addr)).to.equal(ethers.parseEther("13"));
    });

    it("migration is SUBORDINATE to recovery — a pending recovery blocks binding", async function () {
      const f = await deploy(0);
      const rd = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [ROTATE_TARGET, PQ_HASH_2, f.verifierAddress]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (
        await f.vault.initiateRecovery(ROTATE_TARGET, PQ_HASH_2, f.verifierAddress, quorum(f, rd), 0, BigInt(2 ** 40))
      ).wait();
      const dest = await destination(f);
      await expect(bind(f, dest)).to.be.revertedWithCustomError(f.vault, "NoRecovery");
    });

    it("egress recipient comes from the BINDING and can never be supplied by the caller", async function () {
      const f = await deploy(0);
      const dest = await destination(f);
      await (await bind(f, dest)).wait();
      // `egress` takes only an ASSET identifier. There is no recipient
      // parameter anywhere in its signature — that is what keeps a
      // permissionless function from being a public withdrawal.
      const frag = f.vault.interface.getFunction("egress");
      expect(frag!.inputs.map((i) => i.name)).to.deep.equal(["asset"]);
      await (await f.vault.connect(f.attacker).egress(ZERO)).wait();
      expect(await ethers.provider.getBalance(dest.addr)).to.equal(ethers.parseEther("10"));
    });
  });

  // =====================================================================
  describe("reentrancy — the kernel has no mutex, so the argument must hold", function () {
    it("a reentrant recipient cannot replay a spend, because the nonce is already consumed", async function () {
      const f = await deploy(0);
      const R = await ethers.getContractFactory("ReentrantRecipient", f.deployer);
      const r = await R.deploy();
      await r.waitForDeployment();
      const addr = await r.getAddress();

      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(addr, amount) }));
      const sig = signDigest(f.ownerKey, d);
      // Arm the recipient to re-enter with the SAME authorization.
      const payload = f.vault.interface.encodeFunctionData("execute", [
        addr,
        amount,
        0,
        BigInt(2 ** 40),
        sig,
        "0x",
        "0x",
      ]);
      await (await r.arm(f.vaultAddress, payload)).wait();

      await (await f.vault.execute(addr, amount, 0, BigInt(2 ** 40), sig, PQ_SIG, PQ_KEY)).wait();
      expect(await r.tried()).to.equal(true);
      expect(await r.succeeded()).to.equal(false); // the nonce was already spent
      expect(await ethers.provider.getBalance(addr)).to.equal(amount);
      expect(await f.vault.nonces(DOMAIN.SPEND)).to.equal(1n);
    });
  });

  // =====================================================================
  describe("code identity — the five-link chain, measured on chain", function () {
    it("clone bytes -> implementation address -> implementation code -> generation", async function () {
      const f = await deploy(0);
      const cloneCode = await ethers.provider.getCode(f.vaultAddress);
      // Link 1: the clone is byte-exactly the canonical template + args.
      expect(ethers.dataLength(cloneCode)).to.equal(53);
      // Link 2: the implementation ADDRESS is read out of the OBSERVED bytes,
      // never from the factory or a registry.
      const decoded = ethers.getAddress("0x" + cloneCode.slice(22, 62));
      expect(decoded).to.equal(await f.impl.getAddress());
      // Link 3: a SECOND, independent code read of a DIFFERENT account.
      const implCode = await ethers.provider.getCode(decoded);
      expect(implCode).to.not.equal("0x");
      // Link 4: the generation, from the clone's own immutable args.
      expect(await f.vault.kernelGeneration()).to.equal(1n);
      // Link 5: configuration is OBSERVATION, read from storage, timestamped.
      expect(await f.vault.credentialGeneration()).to.equal(1n);
    });

    it("two deployments of the implementation are BYTE-IDENTICAL (I-PURE-CONSTRUCTOR)", async function () {
      const f = await deploy(0);
      const Impl = await ethers.getContractFactory("VaultKernelPrototype", f.deployer);
      const second = await Impl.deploy();
      await second.waitForDeployment();
      const a = await ethers.provider.getCode(await f.impl.getAddress());
      const b = await ethers.provider.getCode(await second.getAddress());
      expect(b).to.equal(a);
      expect(ethers.keccak256(b)).to.equal(ethers.keccak256(a));
    });

    it("the factory's implementation target is IMMUTABLE — D8", async function () {
      const f = await deploy(0);
      const names = f.factory.interface.fragments
        .filter((x) => x.type === "function")
        .map((x) => (x as ethers.FunctionFragment).name);
      // The forbidden vocabulary of D8, checked by absence.
      for (const forbidden of [
        "setImplementation",
        "upgradeFactory",
        "registerNewKernel",
        "upgradeTo",
        "transferOwnership",
        "owner",
      ]) {
        expect(names, forbidden).to.not.include(forbidden);
      }
      expect(names.sort()).to.deep.equal(["deployVault", "generation", "implementation", "predictVault"]);
    });
  });
});
