/**
 * EXPERIMENTAL PROTOTYPE ADMISSION EVIDENCE — NOT PRODUCTION.
 *
 * ASSET IDENTITY IS KERNEL TRUTH: Generation -> Factory -> Clone immutable arguments -> admittedAsset.
 * Rows G2-ASSET-1..10, IMPL-IMMUTABILITY and FACTORY-GENERATION of generation-2/ADMISSION_CRITERIA.json.
 * Every attack carries a positive control on the same world, and every refusal asserts the decoded error,
 * because a probe can die at an earlier guard than the one it claims to reach. The admitted asset is a
 * local mock throughout: no real token is named, modelled or touched.
 */
import { expect } from "chai";
import { ethers } from "./connection.js";
import { GEN2_FACTORY, GEN2_KERNEL, GENERATION_2, gen2Unit } from "../generation-2/compile.js";
import {
  ACTION,
  DEFAULT_MINT,
  DOMAIN,
  ECDSA_ONLY_FLOOR,
  FAR_DEADLINE,
  RECOVERY_DELAY_SECONDS,
  UNIT,
  ZERO,
  addrOf,
  advanceTime,
  assetBalance,
  bindDestination,
  containmentCalldata,
  currentNonce,
  deployGen2World,
  deployUnit,
  digestOf,
  executeRecoveryCalldata,
  guardianDigest,
  keyOf,
  packedArgs,
  pqHash,
  proposeRecovery,
  quorum,
  refusal,
  send,
  sendSpend,
  setPolicyCalldata,
  setVerifierCalldata,
  sign,
  spendCalldata,
  zoo,
  type Gen2World,
} from "../generation-2/world.js";

const PROBE_GAS = 800_000n;
const AMOUNT = 250n * UNIT;
const CLONE_PREFIX = "363d3d373d3d3d363d73";
const CLONE_SUFFIX = "5af43d82803e903d91602b57fd5bf3";
const ERC20_APPEND_MARKER = "deadbeef";

/** Reconstructs the clone's initcode from public facts only: nothing here is read from the factory's code. */
const cloneInitcode = (implementation: string, args: string): string =>
  ethers.concat([
    "0x61",
    ethers.toBeHex(ethers.getBytes(args).length + 45, 2),
    "0x3d81600a3d39f3363d3d373d3d3d363d73",
    implementation,
    "0x" + CLONE_SUFFIX,
    args,
  ]);

const cloneRuntime = (implementation: string, args: string): string =>
  ethers.concat(["0x" + CLONE_PREFIX, implementation, "0x" + CLONE_SUFFIX, args]).toLowerCase();

const ecdsaWorld = (label: string, more: Partial<Parameters<typeof deployGen2World>[0]> = {}): Promise<Gen2World> =>
  deployGen2World({ label, ecdsaOnlyFloor: true, ...more });

async function codeOf(w: Gen2World): Promise<string> {
  return ethers.provider.getCode(w.vaultAddress);
}

describe("Generation-2 admission — asset identity", function () {
  this.timeout(180_000);

  describe("the chain: Generation -> Factory -> Clone immutable args -> admittedAsset, reconstructed offline", function () {
    it("every link is reconstructible from public facts, with nothing read back from the party it is about", async function () {
      const w = await ecdsaWorld("chain");
      const implementation = (await w.factory.implementation()) as string;
      const authority = (await w.factory.verifierAuthority()) as string;

      // Link 1: the implementation's runtime is the compiled artifact, byte for byte (no immutables to link).
      const compiled = gen2Unit(GEN2_KERNEL);
      expect(compiled.immutableReferences, "I-PURE-CONSTRUCTOR: zero immutable slots").to.deep.equal({});
      expect(await ethers.provider.getCode(implementation)).to.equal(compiled.deployedBytecode);

      // Link 2: the factory's generation, root and asset are what its constructor was given.
      expect(await w.factory.generation()).to.equal(GENERATION_2);
      expect(authority).to.equal(w.authorityAddress);
      expect(await w.factory.admittedAsset()).to.equal(w.token);

      // Link 3: the clone is byte-exactly template + implementation + 48 bytes of args (I-CLONE-BYTES-EXACT).
      const args = packedArgs(GENERATION_2, authority, w.token);
      expect(ethers.getBytes(args).length).to.equal(48);
      const code = await codeOf(w);
      expect(ethers.getBytes(code).length).to.equal(93);
      expect(code.toLowerCase()).to.equal(cloneRuntime(implementation, args));

      // Link 4: the address commits to all of it (factory, genesis salt, implementation, args).
      const salt = (await w.vault.genesisSalt(w.salt, w.genesis)) as string;
      expect(
        ethers.getCreate2Address(w.factoryAddress, salt, ethers.keccak256(cloneInitcode(implementation, args))),
      ).to.equal(w.vaultAddress);

      // Link 5: the kernel reads back exactly those fields, from its own code.
      expect(await w.vault.kernelGeneration()).to.equal(GENERATION_2);
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });

    it("the args layout is generation(8) || verifierAuthority(20) || admittedAsset(20), at those exact offsets", async function () {
      const w = await ecdsaWorld("layout");
      const code = ethers.getBytes(await codeOf(w));
      const args = code.slice(45);
      expect(ethers.hexlify(args.slice(0, 8))).to.equal(ethers.toBeHex(GENERATION_2, 8));
      expect(ethers.getAddress(ethers.hexlify(args.slice(8, 28)))).to.equal(w.authorityAddress);
      expect(ethers.getAddress(ethers.hexlify(args.slice(28, 48)))).to.equal(w.token);
    });
  });

  describe("G2-ASSET-1: the asset is fixed at Vault creation", function () {
    it("a vault's asset is its factory's constructor argument, from its first block", async function () {
      const w = await ecdsaWorld("a1");
      expect(await w.vault.admittedAsset()).to.equal(await w.factory.admittedAsset());
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });

    it("the factory's asset is immutable bytes in its own runtime, not a storage word", async function () {
      const w = await ecdsaWorld("a1b");
      const factory = gen2Unit(GEN2_FACTORY);
      expect(
        Object.keys(factory.immutableReferences).length,
        "implementation, generation, verifierAuthority, admittedAsset",
      ).to.equal(4);
      expect(factory.storage, "the factory has no storage at all").to.deep.equal([]);
      const runtime = (await ethers.provider.getCode(w.factoryAddress)).toLowerCase();
      expect(runtime.includes(w.token.slice(2).toLowerCase()), "the asset is in the factory's code").to.equal(true);
    });
  });

  describe("G2-ASSET-2: no setter exists, on the kernel or the factory", function () {
    const stateChanging = (abi: readonly unknown[]): string[] =>
      (abi as { type: string; name: string; stateMutability: string }[])
        .filter((f) => f.type === "function" && f.stateMutability !== "view" && f.stateMutability !== "pure")
        .map((f) => f.name);

    it("the kernel's only functions naming an asset are the view and egress's own argument", function () {
      const abi = gen2Unit(GEN2_KERNEL).abi as {
        type: string;
        name: string;
        stateMutability: string;
        inputs: { name: string }[];
      }[];
      const named = abi
        .filter(
          (f) =>
            f.type === "function" && (/asset|token/i.test(f.name) || f.inputs.some((i) => /asset|token/i.test(i.name))),
        )
        .map((f) => `${f.name}:${f.stateMutability}`);
      expect(named.sort()).to.deep.equal(["admittedAsset:view", "egress:nonpayable"]);
    });

    it("the factory's one state-changing function is deployVault, and it takes no asset", function () {
      const unit = gen2Unit(GEN2_FACTORY);
      expect(stateChanging(unit.abi)).to.deep.equal(["deployVault"]);
      const deployVault = (unit.abi as { name?: string; inputs?: { name: string }[] }[]).find(
        (f) => f.name === "deployVault",
      )!;
      expect(deployVault.inputs!.map((i) => i.name)).to.deep.equal(["userSalt", "g", "pqKey"]);
    });

    it("no storage word of the kernel holds the asset: not by name in the layout, not by value in a live vault", async function () {
      expect(gen2Unit(GEN2_KERNEL).storage.filter((s) => /asset|token/i.test(s.label))).to.deep.equal([]);
      const w = await ecdsaWorld("a2");
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      const needle = w.token.slice(2).toLowerCase();
      for (let slot = 0; slot < 24; slot++) {
        expect(
          (await ethers.provider.getStorage(w.vaultAddress, slot)).toLowerCase().includes(needle),
          `slot ${slot}`,
        ).to.equal(false);
      }
    });

    it("a setter selector dispatches to nothing, on both", async function () {
      const w = await ecdsaWorld("a2c");
      const data = new ethers.Interface(["function setAdmittedAsset(address)"]).encodeFunctionData("setAdmittedAsset", [
        w.otherToken,
      ]);
      for (const to of [w.vaultAddress, w.factoryAddress]) {
        let refused = false;
        try {
          await (await w.deployer.sendTransaction({ to, data, gasLimit: PROBE_GAS })).wait();
        } catch {
          refused = true;
        }
        expect(refused, to).to.equal(true);
      }
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });
  });

  describe("G2-ASSET-3 and G2-ASSET-4: neither a caller nor a relayer selects the asset", function () {
    it("execute has no asset parameter to pass, so the signed digest needs none", function () {
      const execute = (gen2Unit(GEN2_KERNEL).abi as { name?: string; inputs?: { name: string }[] }[]).find(
        (f) => f.name === "execute",
      )!;
      expect(execute.inputs!.map((i) => i.name)).to.deep.equal([
        "recipient",
        "amount",
        "nonce",
        "deadline",
        "ecdsaSig",
        "pqSig",
        "pqKey",
      ]);
    });

    it("a relayer appending another token to honest calldata moves only the admitted asset", async function () {
      const w = await ecdsaWorld("a3");
      await (await w.other.mint(w.vaultAddress, 100n * UNIT)).wait();
      const nonce = await currentNonce(w, DOMAIN.SPEND);
      const honest = spendCalldata(w, { to: w.recipient, amount: AMOUNT, nonce, credentialGeneration: 1n });
      const tampered = honest + w.otherToken.slice(2).toLowerCase() + ERC20_APPEND_MARKER;
      await (await send(w, tampered, w.outsider)).wait();
      expect(await assetBalance(w, w.recipient), "the admitted asset moved").to.equal(AMOUNT);
      expect(await w.other.realBalanceOf(w.vaultAddress), "the other holding did not").to.equal(100n * UNIT);
      expect(await w.other.realBalanceOf(w.recipient)).to.equal(0n);
    });

    it("a relayer rewriting the recipient or the amount is refused, and consumes nothing; relaying it verbatim settles", async function () {
      const w = await ecdsaWorld("a4");
      const nonce = await currentNonce(w, DOMAIN.SPEND);
      const honest = spendCalldata(w, { to: w.recipient, amount: AMOUNT, nonce, credentialGeneration: 1n });
      const decoded = w.vault.interface.decodeFunctionData("execute", honest);
      const hostile = await w.outsider.getAddress();
      const rewrite = (recipient: string, amount: bigint): string =>
        w.vault.interface.encodeFunctionData("execute", [
          recipient,
          amount,
          decoded[2],
          decoded[3],
          decoded[4],
          decoded[5],
          decoded[6],
        ]);
      expect(await refusal(w, () => send(w, rewrite(hostile, AMOUNT), w.outsider, PROBE_GAS))).to.equal("BadSignature");
      expect(await refusal(w, () => send(w, rewrite(w.recipient, AMOUNT * 2n), w.outsider, PROBE_GAS))).to.equal(
        "BadSignature",
      );
      expect(await currentNonce(w, DOMAIN.SPEND)).to.equal(0n);
      await (await send(w, honest, w.outsider)).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
    });

    it("the same relayed spend pays the same recipient whoever submits it: a relayer has no identity to the kernel", async function () {
      const w = await ecdsaWorld("a4b");
      const signers = await ethers.getSigners();
      const data = spendCalldata(w, { to: w.recipient, amount: AMOUNT, nonce: 0n, credentialGeneration: 1n });
      await (await send(w, data, signers[7]!)).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
      expect(await assetBalance(w, await signers[7]!.getAddress())).to.equal(0n);
    });
  });

  describe("G2-ASSET-5 and G2-ASSET-6: no authorised act moves the asset in place", function () {
    it("every credential act leaves the vault's code and asset read byte-identical", async function () {
      const w = await ecdsaWorld("a5");
      const before = await codeOf(w);
      await (await send(w, await setPolicyCalldata(w, w.policies.allow))).wait();
      await (await send(w, await setPolicyCalldata(w, ZERO))).wait();
      await (await send(w, await setVerifierCalldata(w, w.verifiers.honestB, { ...ECDSA_ONLY_FLOOR }))).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT })).wait();
      expect(await codeOf(w)).to.equal(before);
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });

    it("every guardian act, recovery included, leaves them byte-identical too, and the new credential spends the SAME asset", async function () {
      const w = await ecdsaWorld("a6");
      const before = await codeOf(w);
      await (await send(w, await containmentCalldata(w))).wait();
      await advanceTime(3 * 86400 + 1);
      const newCred = keyOf("a6-new-cred");
      const newPq = keyOf("a6-new-pq");
      await (await proposeRecovery(w, addrOf(newCred), pqHash(newPq), w.verifiers.honest)).wait();
      await advanceTime(RECOVERY_DELAY_SECONDS + 1);
      await (await send(w, await executeRecoveryCalldata(w, newCred, newPq, w.verifiers.honest))).wait();
      await (await sendSpend(w, { to: w.recipient, amount: AMOUNT, signer: newCred })).wait();
      expect(await assetBalance(w, w.recipient)).to.equal(AMOUNT);
      expect(await codeOf(w)).to.equal(before);
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });

    it("a replaced roster's quorum cannot move it either", async function () {
      const w = await ecdsaWorld("a6b");
      const before = await codeOf(w);
      const newKeys = [0, 1, 2]
        .map((i) => keyOf("a6b-g" + i))
        .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
      const members = newKeys.map(addrOf);
      const nonce = await currentNonce(w, DOMAIN.GUARDIAN);
      const params = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint64", "address[]", "bool[]"],
          [2n, members, [false, false, false]],
        ),
      );
      const digest = await guardianDigest(w, ACTION.SET_GUARDIANS, params, DOMAIN.GUARDIAN, nonce);
      await (
        await send(
          w,
          w.vault.interface.encodeFunctionData("setGuardians", [
            2n,
            members,
            [false, false, false],
            quorum(w, digest),
            nonce,
            FAR_DEADLINE,
          ]),
        )
      ).wait();
      expect(await w.vault.guardianGeneration()).to.equal(2n);
      expect(await codeOf(w)).to.equal(before);
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });
  });

  describe("G2-ASSET-7: WalletWall owns no asset-selection authority", function () {
    it("the factory exposes no owner, role or registry, and its storage is empty", function () {
      const unit = gen2Unit(GEN2_FACTORY);
      const names = (unit.abi as { type: string; name?: string }[])
        .filter((f) => f.type === "function")
        .map((f) => f.name);
      expect(names.sort()).to.deep.equal([
        "admittedAsset",
        "deployVault",
        "generation",
        "implementation",
        "predictVault",
        "verifierAuthority",
      ]);
      expect(unit.storage).to.deep.equal([]);
    });

    it("the only choice is the constructor's, spent at construction: any deployer gets identical bytes for identical arguments", async function () {
      const w = await ecdsaWorld("a7");
      const signers = await ethers.getSigners();
      const unit = gen2Unit(GEN2_FACTORY);
      const elsewhere = await deployUnit(
        unit,
        signers[6]!,
        await w.factory.implementation(),
        GENERATION_2,
        w.authorityAddress,
        w.token,
      );
      expect(await ethers.provider.getCode(elsewhere.address)).to.equal(
        await ethers.provider.getCode(w.factoryAddress),
      );
      // A clone from it carries the same args, whoever deployed the factory and whoever deployed the clone.
      await (
        await (elsewhere.contract.connect(signers[7]!) as ethers.Contract).deployVault(w.salt, w.genesis, "0x")
      ).wait();
      const twin = (await elsewhere.contract.predictVault(w.salt, w.genesis)) as string;
      expect(await ethers.provider.getCode(twin)).to.equal(await codeOf(w));
    });

    it("the factory's deployer holds no privilege over a clone: a call from it carries no more authority than a stranger's", async function () {
      const w = await ecdsaWorld("a7b");
      const hostile = keyOf("a7b-not-the-credential");
      const deployerAddress = await w.deployer.getAddress();
      expect(
        await refusal(w, () =>
          sendSpend(w, { to: deployerAddress, amount: AMOUNT, signer: hostile, from: w.deployer, gasLimit: PROBE_GAS }),
        ),
      ).to.equal("BadSignature");
    });

    it("a codeless asset, a zero asset, a zero generation and a codeless root cannot be bound at all", async function () {
      const w = await ecdsaWorld("a7c");
      const unit = gen2Unit(GEN2_FACTORY);
      const implementation = (await w.factory.implementation()) as string;
      const deployFails = async (...args: unknown[]): Promise<string> => {
        try {
          await deployUnit(unit, w.deployer, ...args);
          return "DEPLOYED";
        } catch (e) {
          const data = /return data: (0x[0-9a-fA-F]*)/.exec(String(e));
          return data
            ? (new ethers.Interface(unit.abi as ethers.InterfaceAbi).parseError(data[1]!)?.name ?? "UNKNOWN")
            : String(e).slice(0, 100);
        }
      };
      const codeless = addrOf(keyOf("a7c-codeless"));
      expect(await deployFails(implementation, GENERATION_2, w.authorityAddress, codeless)).to.equal("NoCode");
      expect(await deployFails(implementation, GENERATION_2, w.authorityAddress, ZERO)).to.equal("ZeroAddress");
      expect(await deployFails(implementation, 0n, w.authorityAddress, w.token)).to.equal("ZeroGeneration");
      expect(await deployFails(implementation, GENERATION_2, codeless, w.token)).to.equal("NoCode");
      expect(await deployFails(codeless, GENERATION_2, w.authorityAddress, w.token)).to.equal("NoCode");
      // POSITIVE CONTROL: the same call with real arguments deploys.
      expect((await deployUnit(unit, w.deployer, implementation, GENERATION_2, w.authorityAddress, w.token)).address).to
        .be.properAddress;
    });
  });

  describe("G2-ASSET-8: changing the asset requires migrating to a new Vault", function () {
    it("a migration moves the admitted asset to a vault of the same asset, and the destination's credential spends it there", async function () {
      const source = await ecdsaWorld("a8-src");
      // The destination is a real Generation-2 vault of the SAME asset, on its own factory.
      const unit = gen2Unit(GEN2_FACTORY);
      const destFactory = await deployUnit(
        unit,
        source.deployer,
        await source.factory.implementation(),
        GENERATION_2,
        source.authorityAddress,
        source.token,
      );
      const destCred = keyOf("a8-dest-cred");
      const genesis = { ...source.genesis, signer: addrOf(destCred) };
      const destAddress = (await destFactory.contract.predictVault(source.salt, genesis)) as string;
      await (await destFactory.contract.deployVault(source.salt, genesis, "0x")).wait();
      await (
        await bindDestination(source, {
          destination: destAddress,
          codeHash: ethers.keccak256(await ethers.provider.getCode(destAddress)),
        })
      ).wait();
      await advanceTime(7 * 86400 + 1);
      await (await source.vault.connect(source.outsider).getFunction("egress")(source.token)).wait();
      expect(await assetBalance(source, destAddress)).to.equal(DEFAULT_MINT);
      const dest = new ethers.Contract(
        destAddress,
        unit.abi.length ? (gen2Unit(GEN2_KERNEL).abi as ethers.InterfaceAbi) : [],
        source.deployer,
      );
      expect(await dest.admittedAsset()).to.equal(source.token);
      const digest = digestOf({
        chainId: source.chainId,
        vault: destAddress,
        kernelGeneration: GENERATION_2,
        actionType: ACTION.SPEND,
        authorityGeneration: 1n,
        params: ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256"], [source.recipient, AMOUNT]),
        ),
        domain: DOMAIN.SPEND,
        nonce: 0n,
        deadline: FAR_DEADLINE,
      });
      await (await dest.execute(source.recipient, AMOUNT, 0n, FAR_DEADLINE, sign(destCred, digest), "0x", "0x")).wait();
      expect(await assetBalance(source, source.recipient)).to.equal(AMOUNT);
    });

    it("a vault of a DIFFERENT asset holds what arrives as an unsolicited holding: it can leave by egress only, never be spent", async function () {
      const source = await ecdsaWorld("a8b-src");
      const destWorld = await ecdsaWorld("a8b-dst");
      await (
        await bindDestination(source, {
          destination: destWorld.vaultAddress,
          codeHash: ethers.keccak256(await codeOf(destWorld)),
        })
      ).wait();
      await advanceTime(7 * 86400 + 1);
      await (await source.vault.connect(source.outsider).getFunction("egress")(source.token)).wait();
      // The asset of `source` is now at `destWorld`, whose own asset is a different contract.
      expect(await destWorld.vault.admittedAsset()).to.not.equal(source.token);
      const stranded = zoo(source);
      expect(await stranded.realBalanceOf(destWorld.vaultAddress)).to.equal(DEFAULT_MINT);
      await (await sendSpend(destWorld, { to: destWorld.recipient, amount: DEFAULT_MINT })).wait();
      expect(await assetBalance(destWorld, destWorld.recipient), "the spend moved destWorld's own asset").to.equal(
        DEFAULT_MINT,
      );
      expect(await stranded.realBalanceOf(destWorld.vaultAddress), "the unsolicited holding did not move").to.equal(
        DEFAULT_MINT,
      );
      // And a re-binding of the destination is how it leaves: nothing is lost, and nothing was converted.
      await (await bindDestination(destWorld)).wait();
      await advanceTime(7 * 86400 + 1);
      await (await destWorld.vault.connect(destWorld.outsider).getFunction("egress")(source.token)).wait();
      expect(await stranded.realBalanceOf(destWorld.destination)).to.equal(DEFAULT_MINT);
    });

    it("a binding never changes the source vault's asset read", async function () {
      const w = await ecdsaWorld("a8c");
      await (await bindDestination(w)).wait();
      expect(await w.vault.admittedAsset()).to.equal(w.token);
    });
  });

  describe("G2-ASSET-9: a different admitted asset changes the Vault's address, code and signing domain", function () {
    it("with one factory, one salt, one genesis and one implementation, the asset alone moves the CREATE2 address", async function () {
      const w = await ecdsaWorld("a9");
      const implementation = (await w.factory.implementation()) as string;
      const salt = (await w.vault.genesisSalt(w.salt, w.genesis)) as string;
      const at = (asset: string): string =>
        ethers.getCreate2Address(
          w.factoryAddress,
          salt,
          ethers.keccak256(cloneInitcode(implementation, packedArgs(GENERATION_2, w.authorityAddress, asset))),
        );
      expect(at(w.token), "the reconstruction matches the real vault").to.equal(w.vaultAddress);
      expect(at(w.otherToken)).to.not.equal(w.vaultAddress);
    });

    it("two real vaults of two assets, byte-identical genesis: different code, different address, different domain separator", async function () {
      const w = await ecdsaWorld("a9b", { sibling: true });
      const s = w.sibling!;
      expect(s.vaultAddress).to.not.equal(w.vaultAddress);
      expect(await ethers.provider.getCode(s.vaultAddress)).to.not.equal(await codeOf(w));
      expect(await s.vault.domainSeparator()).to.not.equal(await w.vault.domainSeparator());
      expect(await s.vault.ecdsaSigner()).to.equal(await w.vault.ecdsaSigner());
      expect(await s.vault.guardianCommitment()).to.equal(await w.vault.guardianCommitment());
    });
  });

  describe("G2-ASSET-10: cross-asset authorization replay fails, both ways, same credential on both", function () {
    it("a spend signed for this vault fails at the other, and the reverse, and neither burns a nonce; both honest spends then settle", async function () {
      const w = await ecdsaWorld("a10", { sibling: true });
      const s = w.sibling!;
      const here = spendCalldata(w, { to: w.recipient, amount: AMOUNT, nonce: 0n, credentialGeneration: 1n });
      const there = spendCalldata(w, {
        to: w.recipient,
        amount: AMOUNT,
        nonce: 0n,
        credentialGeneration: 1n,
        signForVault: s.vaultAddress,
      });

      const refusedAt = async (to: string, data: string): Promise<string | null> =>
        refusal(w, () => w.outsider.sendTransaction({ to, data, gasLimit: PROBE_GAS }));
      expect(await refusedAt(s.vaultAddress, here), "this vault's signature at the other").to.equal("BadSignature");
      expect(await refusedAt(w.vaultAddress, there), "the other's signature here").to.equal("BadSignature");
      expect(await w.vault.nonces(DOMAIN.SPEND)).to.equal(0n);
      expect(await s.vault.nonces(DOMAIN.SPEND)).to.equal(0n);

      // POSITIVE CONTROL: each at its own vault.
      await (await w.outsider.sendTransaction({ to: w.vaultAddress, data: here })).wait();
      await (await w.outsider.sendTransaction({ to: s.vaultAddress, data: there })).wait();
      expect(await assetBalance(w, w.vaultAddress)).to.equal(DEFAULT_MINT - AMOUNT);
      expect(await s.asset.realBalanceOf(s.vaultAddress)).to.equal(DEFAULT_MINT - AMOUNT);
    });

    it("the two spends are distinct digests only through the vault address, which is what the asset reaches them through", async function () {
      const w = await ecdsaWorld("a10b", { sibling: true });
      const s = w.sibling!;
      const digestFor = (vault: string): string =>
        digestOf({
          chainId: w.chainId,
          vault,
          kernelGeneration: GENERATION_2,
          actionType: ACTION.SPEND,
          authorityGeneration: 1n,
          params: ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256"], [w.recipient, AMOUNT]),
          ),
          domain: DOMAIN.SPEND,
          nonce: 0n,
          deadline: FAR_DEADLINE,
        });
      expect(digestFor(w.vaultAddress)).to.not.equal(digestFor(s.vaultAddress));
    });
  });

  describe("IMPL-IMMUTABILITY and FACTORY-GENERATION", function () {
    it("I-PURE-CONSTRUCTOR: two deployments by two deployers of the implementation have byte-identical runtime", async function () {
      const signers = await ethers.getSigners();
      const a = await deployUnit(gen2Unit(GEN2_KERNEL), signers[3]!);
      const b = await deployUnit(gen2Unit(GEN2_KERNEL), signers[4]!);
      expect(await ethers.provider.getCode(a.address)).to.equal(await ethers.provider.getCode(b.address));
    });

    it("I-DIRECT-IMPL-CALL-INERT: the bare implementation cannot be initialised and moves nothing", async function () {
      const w = await ecdsaWorld("impl");
      const impl = new ethers.Contract(
        (await w.factory.implementation()) as string,
        gen2Unit(GEN2_KERNEL).abi as ethers.InterfaceAbi,
        w.deployer,
      );
      expect(
        await refusal(w, () => impl.getFunction("initialize").send(w.genesis, "0x", { gasLimit: PROBE_GAS })),
      ).to.equal("AlreadyInitialized");
    });

    it("the bare implementation's asset read is its own code bytes read as args: meaningless, and backed by no authority", async function () {
      const w = await ecdsaWorld("impl-asset");
      const impl = new ethers.Contract(
        (await w.factory.implementation()) as string,
        gen2Unit(GEN2_KERNEL).abi as ethers.InterfaceAbi,
        w.deployer,
      );
      expect(await impl.admittedAsset(), "it does not name the admitted asset").to.not.equal(w.token);
      expect(await ethers.provider.getBalance(await impl.getAddress())).to.equal(0n);
      expect(await impl.ecdsaSigner(), "and it has no credential to spend with").to.equal(ZERO);
    });

    it("the factory does not choose the generation number's meaning: it refuses zero and otherwise binds what it was given", async function () {
      const w = await ecdsaWorld("gen-free");
      const unit = gen2Unit(GEN2_FACTORY);
      const another = await deployUnit(
        unit,
        w.deployer,
        await w.factory.implementation(),
        77n,
        w.authorityAddress,
        w.token,
      );
      await (await another.contract.deployVault(w.salt, w.genesis, "0x")).wait();
      const vault = new ethers.Contract(
        (await another.contract.predictVault(w.salt, w.genesis)) as string,
        gen2Unit(GEN2_KERNEL).abi as ethers.InterfaceAbi,
        w.deployer,
      );
      expect(
        await vault.kernelGeneration(),
        "that the publisher wrote 2 is a deployment fact, read from the clone's code",
      ).to.equal(77n);
    });

    it("I-DEPLOY-INIT-ATOMIC: a clone is initialised in its deploying transaction, and once", async function () {
      const w = await ecdsaWorld("atomic");
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(w.credKey));
      expect(
        await refusal(w, () => w.vault.getFunction("initialize").send(w.genesis, "0x", { gasLimit: PROBE_GAS })),
      ).to.equal("AlreadyInitialized");
    });

    it("I-COUNTERFACTUAL-IDENTITY-BINDING: every genesis field moves the address; a stranger with the IDENTICAL config cannot occupy it twice", async function () {
      const w = await ecdsaWorld("salt");
      const predict = (g: unknown): Promise<string> => w.factory.predictVault(w.salt, g) as Promise<string>;
      const base = await predict(w.genesis);
      expect(base).to.equal(w.vaultAddress);
      expect(await predict({ ...w.genesis, signer: addrOf(keyOf("salt-other")) })).to.not.equal(base);
      expect(await predict({ ...w.genesis, verifier: w.verifiers.honestB })).to.not.equal(base);
      expect(await predict({ ...w.genesis, threshold: 3 })).to.not.equal(base);
      expect(await predict({ ...w.genesis, pqKeyHash: pqHash(keyOf("salt-pq")) })).to.not.equal(base);
      expect(await predict({ ...w.genesis, floor: { ...w.genesis.floor, requirePq: true } })).to.not.equal(base);
      const twice = await (async () => {
        try {
          await (
            await w.factory.connect(w.outsider).getFunction("deployVault")(w.salt, w.genesis, "0x", {
              gasLimit: PROBE_GAS,
            })
          ).wait();
          return false;
        } catch {
          return true;
        }
      })();
      expect(twice, "the identity is occupied once").to.equal(true);
    });
  });
});
