/**
 * EXPERIMENTAL PROTOTYPE — NOT PRODUCTION. NOT AUDITED. NO DEPLOYMENT.
 *
 * SCANNER ADJUDICATION PREMISES — executable pins for two FALSE_POSITIVE rationales.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `generate-scanner-evidence.ts --validate` proves that every triage KEY still matches a live
 * Slither finding. It never reads rationale prose, so a rationale can be false while its finding
 * stays byte-stable. Two were:
 *
 *   uninitialized-local  VaultKernelPrototype.egress(address).moved   (semanticId 6e4c498d…)
 *     Said `moved` "is assigned on every path" and "never read before assignment". False: the
 *     ERC-20 branch assigns only inside `if (before != 0)`, and the emit reads the zero default
 *     when the vault holds none of the asset.
 *
 *   reentrancy-events    VaultKernelFactoryPrototype.deployVault       (semanticId 951fd542…)
 *     Said the clone's `initialize` "makes no external call". False since SD-11 (b058715b):
 *     `initialize` calls `_requireAdmissibleVerifier`, one STATICCALL to the verifier authority
 *     the factory bound. Slither's message names only the outer `initialize(g,pqKey)` call, so the
 *     finding never changed and the entry was carried forward unre-read.
 *
 * Both classifications stay FALSE_POSITIVE under corrected arguments. This file pins the premises
 * those corrected arguments rest on, by EXECUTION against the real kernel and factory artifacts:
 *
 *   P-148  zero-balance ERC-20 egress succeeds, moves nothing and emits Egressed(asset, dest, 0).
 *   P-349  a verifier authority that calls back into deployVault from isAdmissibleVerifier runs
 *          under STATICCALL, so the callback cannot CREATE2, SSTORE or LOG: no second vault, no
 *          second VaultDeployed, factory unchanged, and the outer clone cannot be re-initialised.
 *
 * Every attack is paired with a POSITIVE CONTROL that reaches the same seam, so a refusal is
 * attributable to the premise and not to broken setup:
 *   P-148  the same hostile token WITH a balance makes egress revert, so its transfer IS reached
 *          whenever the kernel calls it; a funded token moves and reports its full amount.
 *   P-349  the SAME callback from an ordinary CALL frame does create a vault; and a kernel mutant
 *          whose admission check uses CALL instead of STATICCALL lets the reentrant deployment
 *          through. The STATICCALL is therefore what stops it, not the fixture or the gas.
 *
 * Section G ties the committed triage text to this file, so the two rationales cannot drift back
 * to the withdrawn premises without a red test. It checks named phrases and a citation; it does
 * not, and cannot, prove English prose true.
 *
 * NOTHING HERE IS ADDED TO `contracts/`. The hostile authority is compiled in memory by the pinned
 * solc (sd11-verifier-compile.ts); `contracts/` is the scanner input scope, and one new file there
 * would move `contractsTree` and invalidate the committed scanner receipt. No `setCode`, no
 * `setStorageAt`: every contract is created by an ordinary transaction.
 */
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { ethers } from "./connection.js";
import { compileSources, type Deployable } from "./sd11-verifier-compile.js";
import { compileDeployable, type DeployableMutant } from "../stateful/mutants.js";
import { quorum, KERNEL_GEN } from "./sd4-harness.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  HONEST_FLOOR,
  addrOf,
  deployWorld,
  digestOf,
  floorTuple,
  keyOf,
  migrationParams,
  pqHash,
  pqKeyBytes,
  sign,
  type World,
} from "../stateful/world.js";

const DIR = path.join("prototype", "vnext-kernel");
const TRIAGE_PATH = path.join(DIR, "slither-triage.json");
const KERNEL_PATH = path.join(DIR, "contracts", "VaultKernelPrototype.sol");
const THIS_FILE = "test/ScannerAdjudicationPremises.test.ts";

/** The two semantic identities whose rationales this file pins (GitHub code-scanning #148, #349). */
const MOVED_ID = "6e4c498d3bd894e9f50a1287e2f5d16935a6fb9ca0ba7dff1f832a6b6428e090";
const DEPLOY_VAULT_ID = "951fd542bfda583b589d5977d56cd31a7c66129b9e429755fc59e0c123dbbaf0";

// =====================================================================================
// P-148 helpers
// =====================================================================================

/** Binds the world's destination with an honest quorum AND the credential (cut k + 1). */
async function bindMigration(w: World): Promise<void> {
  const nonce = (await w.vault.nonces(DOMAIN.MIGRATION)) as bigint;
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const destination = { vault: w.destination, codeHash: w.destinationCodeHash, generation: 2n };
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: gGen,
    params: migrationParams(destination.vault, destination.codeHash, destination.generation),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.bindMigration(
      [destination.vault, destination.codeHash, destination.generation],
      quorum(w, digest),
      nonce,
      FAR_DEADLINE,
      sign(w.credKey, digest),
    )
  ).wait();
}

/** Every kernel field egress could conceivably disturb, plus the balances around it. */
async function kernelSnapshot(w: World, tokens: string[]): Promise<unknown> {
  const v = w.vault;
  const balances = await Promise.all(
    tokens.map(async (t) => {
      const tok = await ethers.getContractAt("TestToken", t);
      return [t, String(await tok.balanceOf(w.vaultAddress)), String(await tok.balanceOf(w.destination))];
    }),
  );
  return JSON.parse(
    JSON.stringify(
      {
        safeState: await v.safeState(),
        migration: await v.migration(),
        nonces: await Promise.all([0, 1, 2, 3].map((d) => v.nonces(d))),
        ecdsaSigner: await v.ecdsaSigner(),
        pqPublicKeyHash: await v.pqPublicKeyHash(),
        pqVerifier: await v.pqVerifier(),
        guardianCommitment: await v.guardianCommitment(),
        guardianThreshold: await v.guardianThreshold(),
        guardianGeneration: await v.guardianGeneration(),
        credentialGeneration: await v.credentialGeneration(),
        containedUntil: await v.containedUntil(),
        securityFloor: await v.securityFloor(),
        recovery: await v.recovery(),
        nativeVault: await ethers.provider.getBalance(w.vaultAddress),
        nativeDestination: await ethers.provider.getBalance(w.destination),
        balances,
      },
      (_k, x) => (typeof x === "bigint" ? x.toString() : x),
    ),
  );
}

// =====================================================================================
// P-349 fixture and helpers
// =====================================================================================

/**
 * A HOSTILE verifier authority. It exposes the kernel's `isAdmissibleVerifier(address)` selector.
 * When the armed clone asks, it first tries the armed callbacks; it always answers "admissible".
 *
 * `isAdmissibleVerifier` is deliberately NOT declared view: the compiler would otherwise refuse the
 * CALLs. The kernel still reaches it through STATICCALL, because the kernel's own interface
 * (IKernelPlanes.sol, IKernelVerifierAuthority) declares it view — that is the premise under test.
 *
 * `note()` is how the fixture reports what happened WITHOUT relying on a trace. It is itself
 * reached through a CALL, so from a STATICCALL frame the write fails and the attempt is simply lost;
 * `writeProbe` records whether this frame could write at all. `probe()` replays the identical
 * callbacks from an ordinary CALL frame: the positive control.
 */
const HOSTILE_AUTHORITY_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract PremiseReenteringVerifierAuthority {
    /// Gas handed to each callback. The positive control proves it suffices for a whole deployVault.
    uint256 public constant CALLBACK_GAS = 3_000_000;

    address public trigger;
    address[] public targets;
    bytes[] public payloads;

    uint256 public attempts;
    uint256 public successes;
    uint256 public admissionQueries;

    function arm(address trigger_, address[] calldata targets_, bytes[] calldata payloads_) external {
        require(targets_.length == payloads_.length, "shape");
        trigger = trigger_;
        delete targets;
        delete payloads;
        for (uint256 i = 0; i < targets_.length; i++) {
            targets.push(targets_[i]);
            payloads.push(payloads_[i]);
        }
        attempts = 0;
        successes = 0;
        admissionQueries = 0;
    }

    /// Reenters only when the ARMED clone asks, so a vault created by a callback is admitted quietly
    /// instead of recursing.
    function isAdmissibleVerifier(address) external returns (bool) {
        if (msg.sender == trigger) _reenter();
        return true;
    }

    function probe() external {
        _reenter();
    }

    function note(uint256 attempted, uint256 succeeded) external {
        require(msg.sender == address(this), "self only");
        attempts += attempted;
        successes += succeeded;
        admissionQueries += 1;
    }

    function _reenter() internal {
        uint256 n = targets.length;
        uint256 ok;
        for (uint256 i = 0; i < n; i++) {
            (bool s, ) = targets[i].call{gas: CALLBACK_GAS}(payloads[i]);
            if (s) ok += 1;
        }
        // From a STATICCALL frame this CALL cannot SSTORE, so it fails and the note is lost.
        (bool wrote, ) = address(this).call{gas: 200_000}(abi.encodeCall(this.note, (n, ok)));
        wrote;
    }
}
`;

interface Genesis {
  signer: string;
  pqKeyHash: string;
  verifier: string;
  threshold: number;
  guardians: string[];
  guardianIsContract: boolean[];
  floor: [boolean, number, number, number];
}

function genesisFor(label: string, verifier: string): { genesis: Genesis; witness: string } {
  const credKey = keyOf(label + "-cred");
  const pqKey = keyOf(label + "-pq");
  const gKeys = [0, 1, 2]
    .map((i) => keyOf(label + "-guardian-" + i))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  return {
    genesis: {
      signer: addrOf(credKey),
      pqKeyHash: pqHash(pqKey),
      verifier,
      threshold: 2,
      guardians: gKeys.map(addrOf),
      guardianIsContract: [false, false, false],
      floor: floorTuple(HONEST_FLOOR),
    },
    witness: pqKeyBytes(pqKey),
  };
}

const REENTRY_GAS = 12_000_000n;

interface ReentryWorld {
  authority: ethers.Contract;
  factory: ethers.Contract;
  implAddress: string;
  verifier: string;
  outer: { salt: string; genesis: Genesis; witness: string; address: string };
  inner: { salt: string; genesis: Genesis; witness: string; address: string };
}

async function reentryWorld(
  label: string,
  hostile: Deployable,
  implOverride?: DeployableMutant,
): Promise<ReentryWorld> {
  const [deployer] = await ethers.getSigners();

  const authority = (await new ethers.ContractFactory(
    hostile.abi as ethers.InterfaceAbi,
    hostile.bytecode,
    deployer,
  ).deploy()) as unknown as ethers.Contract;
  await authority.waitForDeployment();

  const Impl = implOverride
    ? new ethers.ContractFactory(implOverride.abi as ethers.InterfaceAbi, implOverride.bytecode, deployer)
    : await ethers.getContractFactory("VaultKernelPrototype", deployer);
  const impl = await Impl.deploy();
  await impl.waitForDeployment();

  const Factory = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
  const factory = (await Factory.deploy(
    await impl.getAddress(),
    1,
    await authority.getAddress(),
  )) as unknown as ethers.Contract;
  await factory.waitForDeployment();

  // A verifier with code; the hostile authority approves anything, so which one does not matter.
  const V = await ethers.getContractFactory("EcdsaBackedVerifier", deployer);
  const v = await V.deploy();
  await v.waitForDeployment();
  const verifier = await v.getAddress();

  const outerG = genesisFor(label + "-outer", verifier);
  const innerG = genesisFor(label + "-inner", verifier);
  const outerSalt = ethers.id(label + "-outer-vault");
  const innerSalt = ethers.id(label + "-inner-vault");
  const outerAddress = (await factory.predictVault(outerSalt, outerG.genesis)) as string;
  const innerAddress = (await factory.predictVault(innerSalt, innerG.genesis)) as string;

  // Callback 1: a reentrant deployVault of a DIFFERENT vault. Callback 2: re-run initialize on the
  // outer clone itself with an attacker genesis — the "reclaim _initialized" shape.
  const attacker = genesisFor(label + "-attacker", verifier);
  await (
    await authority.arm(
      outerAddress,
      [await factory.getAddress(), outerAddress],
      [
        factory.interface.encodeFunctionData("deployVault", [innerSalt, innerG.genesis, innerG.witness]),
        impl.interface.encodeFunctionData("initialize", [attacker.genesis, attacker.witness]),
      ],
    )
  ).wait();

  return {
    authority,
    factory,
    implAddress: await impl.getAddress(),
    verifier,
    outer: { salt: outerSalt, ...outerG, address: outerAddress },
    inner: { salt: innerSalt, ...innerG, address: innerAddress },
  };
}

function vaultDeployedLogs(receipt: ethers.TransactionReceipt, factory: ethers.Contract): ethers.LogDescription[] {
  const factoryAddress = String(factory.target).toLowerCase();
  return receipt.logs
    .filter((l) => l.address.toLowerCase() === factoryAddress)
    .map((l) => factory.interface.parseLog(l))
    .filter((d): d is ethers.LogDescription => d !== null && d.name === "VaultDeployed");
}

async function factorySnapshot(f: ethers.Contract): Promise<unknown> {
  const address = String(f.target);
  return {
    implementation: await f.implementation(),
    generation: String(await f.generation()),
    verifierAuthority: await f.verifierAuthority(),
    codeHash: ethers.keccak256(await ethers.provider.getCode(address)),
    // The factory declares no storage; slot 0 is where a first variable would live.
    slot0: await ethers.provider.getStorage(address, 0),
  };
}

// =====================================================================================

describe("Scanner adjudication premises — #148 (egress `moved`) and #349 (deployVault reentrancy-events)", function () {
  this.timeout(900_000);

  describe("P-148 — zero-balance ERC-20 egress yields movement 0", function () {
    it("P-148 a bound vault holding NONE of an ERC-20 egresses it: success, nothing moves, Egressed(asset, destination, 0), nothing else changes", async function () {
      const w = await deployWorld({ label: "premise-148" });
      await bindMigration(w);
      expect(await w.vault.safeState()).to.equal(3n); // MIGRATION_ONLY: the binding took

      // A token that REVERTS on transfer. With a zero balance, a successful egress therefore proves
      // the kernel never called transfer — the `if (before != 0)` branch was skipped.
      const Token = await ethers.getContractFactory("TestToken", w.deployer);
      const hostile = await Token.deploy(true);
      await hostile.waitForDeployment();
      const asset = await hostile.getAddress();
      expect(await hostile.balanceOf(w.vaultAddress)).to.equal(0n);

      const tokens = [asset, w.token];
      const before = await kernelSnapshot(w, tokens);
      const receipt = (await (await w.vault.connect(w.outsider).egress(asset)).wait())!;
      expect(receipt.status).to.equal(1);

      // Exactly one log, and it is Egressed(asset, destination, 0).
      expect(receipt.logs).to.have.length(1);
      const parsed = w.vault.interface.parseLog(receipt.logs[0]!)!;
      expect(parsed.name).to.equal("Egressed");
      expect(parsed.args.asset).to.equal(asset);
      expect(parsed.args.destination).to.equal(w.destination);
      expect(parsed.args.amount).to.equal(0n);
      await expect(w.vault.egress(asset)).to.emit(w.vault, "Egressed").withArgs(asset, w.destination, 0n);

      expect(await hostile.balanceOf(w.destination)).to.equal(0n);
      expect(await kernelSnapshot(w, tokens)).to.deep.equal(before);
    });

    it("P-148 POSITIVE CONTROL — the same hostile token WITH a balance is reached and refused; a funded token moves its full amount", async function () {
      const w = await deployWorld({ label: "premise-148-control" });
      await bindMigration(w);

      const Token = await ethers.getContractFactory("TestToken", w.deployer);
      const hostile = await Token.deploy(true);
      await hostile.waitForDeployment();
      await (await hostile.mint(w.vaultAddress, 1n)).wait();
      // before != 0, so transfer IS called, and this token reverts it.
      await expect(w.vault.egress(await hostile.getAddress())).to.be.revertedWithCustomError(w.vault, "TransferFailed");

      // The world token was minted 5 ether to the vault at deployment: moved = before - remaining.
      const funded = ethers.parseEther("5");
      await expect(w.vault.egress(w.token)).to.emit(w.vault, "Egressed").withArgs(w.token, w.destination, funded);
      const tok = await ethers.getContractAt("TestToken", w.token);
      expect(await tok.balanceOf(w.destination)).to.equal(funded);
      // And once drained, the same token is the zero case again.
      await expect(w.vault.egress(w.token)).to.emit(w.vault, "Egressed").withArgs(w.token, w.destination, 0n);
    });

    it("P-148 the construct the premise describes is the one in the source (no initializer; assignment only under before != 0)", function () {
      const src = fs.readFileSync(KERNEL_PATH, "utf8");
      const start = src.indexOf("function egress(address asset) external {");
      expect(start, "egress not found").to.be.greaterThan(-1);
      const body = src.slice(start, src.indexOf("function _balanceOf(", start));
      expect(body).to.include("        uint256 moved;\n");
      expect(body).to.include("            moved = address(this).balance;\n");
      expect(body).to.match(/if \(before != 0\) \{[\s\S]*moved = before - remaining;[\s\S]*?\}\n        \}/);
      expect(body).to.include("emit Egressed(asset, b.destinationVault, moved);");
    });
  });

  describe("P-349 — the verifier-authority callback runs under STATICCALL and cannot statefully reenter deployVault", function () {
    let HOSTILE: Deployable;
    let CALL_MUTANT: DeployableMutant;

    before(function () {
      const out = compileSources({ "PremiseReenteringVerifierAuthority.sol": HOSTILE_AUTHORITY_SOURCE });
      const hostile = out.get("PremiseReenteringVerifierAuthority");
      if (hostile === undefined) throw new Error("hostile authority fixture did not compile");
      HOSTILE = hostile;

      // CONSTRUCTED_CONTROL: the admission check with the static context removed. Everything else,
      // including `_initialized = true` before the check, is the real kernel.
      const anchor =
        "    function _requireAdmissibleVerifier(address verifier) internal view {\n" +
        "        if (!IKernelVerifierAuthority(_verifierAuthority()).isAdmissibleVerifier(verifier)) revert InadmissibleVerifier();\n" +
        "    }\n";
      const src = fs.readFileSync(KERNEL_PATH, "utf8");
      expect(src.split(anchor).length - 1, "mutation anchor must occur exactly once").to.equal(1);
      const mutated = src.replace(
        anchor,
        "    function _requireAdmissibleVerifier(address verifier) internal {\n" +
          "        (bool ok, bytes memory ret) = _verifierAuthority().call(\n" +
          "            abi.encodeWithSelector(IKernelVerifierAuthority.isAdmissibleVerifier.selector, verifier)\n" +
          "        );\n" +
          "        if (!ok || ret.length < 32 || !abi.decode(ret, (bool))) revert InadmissibleVerifier();\n" +
          "    }\n",
      );
      const compiled = compileDeployable({ "VaultKernelPrototype.sol": mutated });
      if (!compiled.ok) throw new Error("CALL mutant failed to compile:\n" + compiled.errors.join("\n"));
      CALL_MUTANT = compiled.kernel;
    });

    it("P-349 the premises in the source: _initialized is set before the one authority interaction, and that interaction is a view call", function () {
      const src = fs.readFileSync(KERNEL_PATH, "utf8");
      const init = src.slice(
        src.indexOf("function initialize(GenesisConfig calldata g, bytes calldata pqKey) external {"),
      );
      const flag = init.indexOf("_initialized = true;");
      const check = init.indexOf("_requireAdmissibleVerifier(g.verifier);");
      expect(flag).to.be.greaterThan(-1);
      expect(check).to.be.greaterThan(flag);
      expect(src).to.include("function _requireAdmissibleVerifier(address verifier) internal view {");
      const iface = fs.readFileSync(path.join(DIR, "contracts", "interfaces", "IKernelPlanes.sol"), "utf8");
      expect(iface).to.include("function isAdmissibleVerifier(address verifier) external view returns (bool);");
      // The factory holds no mutable state: every declared variable is immutable.
      const factory = fs.readFileSync(path.join(DIR, "contracts", "VaultKernelFactoryPrototype.sol"), "utf8");
      const stateVars = factory.match(/^ {4}(address|uint\d+|bytes32|bool|mapping)[^;(]*;/gm) ?? [];
      expect(stateVars.length).to.equal(3);
      for (const v of stateVars) expect(v).to.include(" immutable ");
    });

    it("P-349 ATTACK — a hostile authority calls back into deployVault and initialize during admission; the callbacks fail and the outer deployment is the only one", async function () {
      const r = await reentryWorld("premise-349", HOSTILE);
      const factoryBefore = await factorySnapshot(r.factory);
      const createsBefore = await ethers.provider.getTransactionCount(String(r.factory.target));

      const tx = await r.factory.deployVault(r.outer.salt, r.outer.genesis, r.outer.witness, { gasLimit: REENTRY_GAS });
      const receipt = (await tx.wait())!;
      expect(receipt.status).to.equal(1);

      // (1) the callback attempt is made: the trace shows the authority's CALL into the factory's
      //     deployVault, reached through the kernel's STATICCALL, and that frame failing.
      const trace = await callTrace(receipt.hash);
      const admission = findFrame(trace, (f) => f.type === "STATICCALL" && eqAddr(f.to, r.authority.target));
      expect(admission, "the kernel consulted the authority").to.not.equal(undefined);
      const reentry = (admission!.calls ?? []).find(
        (f) =>
          eqAddr(f.to, r.factory.target) &&
          f.input.startsWith(r.factory.interface.getFunction("deployVault")!.selector),
      );
      expect(reentry, "the authority attempted to reenter deployVault").to.not.equal(undefined);
      expect(reentry!.type).to.equal("CALL");
      // The EVM's own verdict on that frame: it tried to change state inside a static context.
      expect(reentry!.error).to.equal("StateChangeDuringStaticCall");
      const reinit = (admission!.calls ?? []).find((f) => eqAddr(f.to, r.outer.address));
      expect(reinit, "the authority attempted to re-run initialize on the outer clone").to.not.equal(undefined);
      // Refused by the kernel before any write: `_initialized` was set before the authority was asked.
      expect(reinit!.error).to.equal("execution reverted");
      const outerKernel = await ethers.getContractAt("VaultKernelPrototype", r.outer.address);
      expect(reinit!.output).to.equal(outerKernel.interface.getError("AlreadyInitialized")!.selector);

      // (2) no second vault exists.
      expect(await ethers.provider.getCode(r.inner.address)).to.equal("0x");
      // (3) exactly one VaultDeployed, for the outer vault.
      const events = vaultDeployedLogs(receipt, r.factory);
      expect(events).to.have.length(1);
      expect(events[0]!.args.vault).to.equal(r.outer.address);
      // (4) the factory is unchanged, and it created exactly ONE contract in this transaction (its
      //     account nonce counts CREATE2s): the outer clone.
      expect(await factorySnapshot(r.factory)).to.deep.equal(factoryBefore);
      expect(await ethers.provider.getTransactionCount(String(r.factory.target))).to.equal(createsBefore + 1);
      // The authority could not even record the attempt: its own write was refused in that frame.
      expect(await r.authority.admissionQueries()).to.equal(0n);

      // (5) the legitimate outer deployment succeeded with the genesis the deployer chose, not the
      //     attacker genesis the callback tried to install.
      const outer = await ethers.getContractAt("VaultKernelPrototype", r.outer.address);
      expect(await outer.ecdsaSigner()).to.equal(r.outer.genesis.signer);
      expect(await outer.pqPublicKeyHash()).to.equal(r.outer.genesis.pqKeyHash);
      expect(await outer.pqVerifier()).to.equal(r.verifier);
      expect(await outer.safeState()).to.equal(0n); // NORMAL

      // (6) _initialized cannot be reclaimed: a later initialize on the outer clone is refused.
      const again = genesisFor("premise-349-late", r.verifier);
      await expect(outer.initialize(again.genesis, again.witness)).to.be.revertedWithCustomError(
        outer,
        "AlreadyInitialized",
      );
      expect(await outer.ecdsaSigner()).to.equal(r.outer.genesis.signer);
    });

    it("P-349 POSITIVE CONTROL — the identical callback from an ordinary CALL frame DOES deploy the second vault", async function () {
      const r = await reentryWorld("premise-349-probe", HOSTILE);
      // Outer vault first, exactly as in the attack.
      await (
        await r.factory.deployVault(r.outer.salt, r.outer.genesis, r.outer.witness, { gasLimit: REENTRY_GAS })
      ).wait();
      expect(await ethers.provider.getCode(r.inner.address)).to.equal("0x");

      const receipt = (await (await r.authority.probe({ gasLimit: REENTRY_GAS })).wait())!;
      expect(receipt.status).to.equal(1);
      // Outside a static context the payload is a valid, working deployVault: the vault appears and
      // the factory logs it. So the refusal above was not a malformed payload or a gas shortfall.
      expect(await ethers.provider.getCode(r.inner.address)).to.not.equal("0x");
      const events = vaultDeployedLogs(receipt, r.factory);
      expect(events).to.have.length(1);
      expect(events[0]!.args.vault).to.equal(r.inner.address);
      // The note write also lands from an ordinary frame: 2 callbacks attempted, 1 succeeded (the
      // deployVault); the initialize on the already-initialised outer clone is refused.
      expect(await r.authority.admissionQueries()).to.equal(1n);
      expect(await r.authority.attempts()).to.equal(2n);
      expect(await r.authority.successes()).to.equal(1n);
    });

    it("P-349 CONSTRUCTED_CONTROL — with the admission call made by CALL instead of STATICCALL, the same authority DOES reenter deployVault", async function () {
      const r = await reentryWorld("premise-349-mutant", HOSTILE, CALL_MUTANT);
      const createsBefore = await ethers.provider.getTransactionCount(String(r.factory.target));
      const receipt = (await (
        await r.factory.deployVault(r.outer.salt, r.outer.genesis, r.outer.witness, { gasLimit: REENTRY_GAS })
      ).wait())!;
      expect(receipt.status).to.equal(1);

      // The reentrant deployment now happens INSIDE the outer one: a second vault and a second event.
      expect(await ethers.provider.getCode(r.inner.address)).to.not.equal("0x");
      const events = vaultDeployedLogs(receipt, r.factory);
      expect(events.map((e) => e.args.vault)).to.have.members([r.inner.address, r.outer.address]);
      expect(await ethers.provider.getTransactionCount(String(r.factory.target))).to.equal(createsBefore + 2);
      expect(await r.authority.admissionQueries()).to.be.greaterThan(0n);

      // Even here the outer clone keeps the deployer's genesis: `_initialized = true` precedes the
      // authority call, so the callback's initialize on the outer clone is refused.
      const outer = await ethers.getContractAt("VaultKernelPrototype", r.outer.address);
      expect(await outer.ecdsaSigner()).to.equal(r.outer.genesis.signer);
    });
  });

  describe("G — the committed triage rationales cite these premises and not the withdrawn ones", function () {
    const triage = (): Record<string, { classification: string; rationale: string }> =>
      JSON.parse(fs.readFileSync(TRIAGE_PATH, "utf8")).classifications;

    for (const [id, alert, withdrawn] of [
      [MOVED_ID, "#148", [/assigned on every path/i, /never read before assignment/i]],
      [DEPLOY_VAULT_ID, "#349", [/makes no external call/i, /initialize[^.]*\bno external call/i]],
    ] as const) {
      it(`G ${alert} (${id.slice(0, 8)}) stays FALSE_POSITIVE, cites ${THIS_FILE}, and carries no withdrawn premise`, function () {
        const entry = triage()[id];
        expect(entry, "triage entry present").to.not.equal(undefined);
        expect(entry!.classification).to.equal("FALSE_POSITIVE");
        expect(entry!.rationale).to.include(THIS_FILE);
        for (const phrase of withdrawn) expect(entry!.rationale).to.not.match(phrase);
      });
    }
  });
});

// =====================================================================================
// Call tracing
// =====================================================================================

interface CallFrame {
  type: string;
  from: string;
  to: string;
  input: string;
  output?: string;
  error?: string;
  calls?: CallFrame[];
}

const eqAddr = (a: unknown, b: unknown): boolean => String(a).toLowerCase() === String(b).toLowerCase();

function findFrame(root: CallFrame, pred: (f: CallFrame) => boolean): CallFrame | undefined {
  if (pred(root)) return root;
  for (const c of root.calls ?? []) {
    const hit = findFrame(c, pred);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

async function callTrace(hash: string): Promise<CallFrame> {
  return (await ethers.provider.send("debug_traceTransaction", [hash, { tracer: "callTracer" }])) as CallFrame;
}
