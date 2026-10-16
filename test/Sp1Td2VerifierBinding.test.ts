/**
 * SP1-TD2 — the binding gate in the deployment and rotation tooling (scripts/lib/verifier-binding.ts;
 * docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
 *
 *   EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER — WalletWallMultiSigVault, kept outside the halt until its gate
 *     TD2-MULTISIG-ROTATION is built, tested and admitted by the owner, is refused a haltable wrapper (and any other
 *     part of the SP1 path) by the deployment and rotation tooling; the consumers in scope are not.
 *   TD1-N12, recovery-target gating BY PROCESS — a target on the SP1 path must be a ZKMLDSAVerifier compiled from
 *     this tree, ACTIVE, not haltable by the signer, of no identity halted at the consumer or at any wrapper in the
 *     registry; and, without the local override, registered, the only ACTIVE registered wrapper of its identity,
 *     and designated (SP1-TD1's designation, or a successor's).
 *
 * Scope and SP1-TD1's designation are read from its receipt; this suite checks that they are, then exercises the
 * gate's rules on profiles measured from deployed contracts (the real v6.1.0 bytes included), each refusal with a
 * positive control.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect } from "chai";
import assert from "node:assert/strict";

import { ethers, networkHelpers } from "./helpers/connection";
import { ROTATION_DELAY, VKEY_A, VKEY_B, deploySp1, deployWrapper } from "./helpers/td2Helpers";
import {
  CONSUMERS,
  WRAPPER_REGISTRY_SCHEMA,
  ZK_ALGORITHM_ID,
  bindingRefusals,
  checkDeploymentBinding,
  checkRotationBinding,
  identifyConsumer,
  isExecutionFailure,
  isHaltable,
  isOnSp1Path,
  matchesWrapperArtifact,
  profileVerifier,
  readDesignations,
  readHaltScope,
  readWrapperArtifact,
  readWrapperRegistry,
  wrapperRegistryErrors,
  type BindingRequest,
  type Designation,
  type VerifierProfile,
} from "../scripts/lib/verifier-binding";

const TD1 = JSON.parse(readFileSync(resolve("evidence/zk/sp1-td1/decision-receipt.json"), "utf8"));
const BYTECODE = JSON.parse(
  readFileSync(resolve("evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json"), "utf8"),
);
const SEPOLIA = 11155111n;
const LOCAL = 31337n;
const MOCK_OK = { allowMockSp1: true };

describe("SP1-TD2 verifier binding gate (deployment and rotation tooling)", function () {
  let admin: any, haltPrincipal: any, otherHaltPrincipal: any, stranger: any;
  let sp1: any, haltable: any, unhaltable: any, mock: any;

  beforeEach(async function () {
    [admin, haltPrincipal, otherHaltPrincipal, stranger] = await ethers.getSigners();
    sp1 = await deploySp1();
    haltable = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
    unhaltable = await (
      await ethers.getContractFactory("UnhaltableZkVerifierMock")
    ).deploy(await sp1.getAddress(), VKEY_A);
    mock = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
  });

  const request = (target: VerifierProfile, overrides: Partial<BindingRequest> = {}): BindingRequest => ({
    consumer: "WalletWallVault",
    target,
    chainId: SEPOLIA,
    signer: admin.address,
    allowMockSp1: false,
    current: null,
    currentIdentity: null,
    targetIdentityRecordedHalted: false,
    scope: readHaltScope(),
    designations: readDesignations(),
    registered: [],
    ...overrides,
  });
  /** A request for a target that is registered (the only ACTIVE wrapper of its identity) on the chain. */
  const registeredRequest = (target: VerifierProfile, overrides: Partial<BindingRequest> = {}) =>
    request(target, { registered: [target], ...overrides });

  describe("inputs come from the SP1-TD1 receipt and the wrapper registry, never typed", function () {
    it("the halt scope is the owner's amended scope: three consumers, the multisig vault excluded under its own gate", function () {
      const frozen = TD1.decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope;
      expect(readHaltScope()).to.deep.equal(frozen);
      expect(readHaltScope().applies).to.deep.equal([
        "PolicyControlBridge",
        "StablecoinVaultSimulator",
        "WalletWallVault",
      ]);
      expect(readHaltScope().excludedUntilRecoverable).to.deep.equal([
        {
          consumer: "WalletWallMultiSigVault",
          gate: "TD2-MULTISIG-ROTATION",
          interim: "NOT_BOUND_TO_THE_SP1_PATH",
          authorizedBy: "TD1-N11-PREREQUISITE",
        },
      ]);
      expect([...CONSUMERS].sort()).to.deep.equal([...TD1.decisions.DEFECT_RESPONSE_COUPLING.measuredConsumers].sort());
    });

    it("SP1-TD1's designation is the trust target's code hash (per chain) and the designated PROGRAM_VKEY", function () {
      const designations = readDesignations();
      expect(designations).to.have.length(1);
      const [d] = designations;
      expect(d.sp1VerifierCodeKeccak).to.equal(TD1.trustTarget.codeKeccak);
      expect(d.programVKey).to.equal(TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey);
      expect(Object.keys(d.sp1VerifierCodeKeccakByChain).sort()).to.deep.equal(["1", "11155111", "8453", "84532"]);
      for (const c of TD1.trustTarget.chains) expect(d.sp1VerifierCodeKeccakByChain[c.chainId]).to.equal(c.codeKeccak);
    });

    it("the committed wrapper registry is well formed and empty: no wrapper is deployed anywhere yet", function () {
      const doc = JSON.parse(readFileSync(resolve("evidence/zk/sp1-td2/wrapper-registry.json"), "utf8"));
      expect(wrapperRegistryErrors(doc)).to.deep.equal([]);
      expect(doc.entries).to.deep.equal([]);
      for (const chain of [1n, 8453n, SEPOLIA, 84532n, LOCAL]) expect(readWrapperRegistry(chain)).to.deep.equal([]);
    });

    it("a registry document is refused unless every entry names a decimal chain id and an address, once", function () {
      const entry = { chainId: "11155111", address: stranger.address };
      expect(wrapperRegistryErrors({ schema: WRAPPER_REGISTRY_SCHEMA, entries: [entry] })).to.deep.equal([]);
      const cases: [string, unknown, RegExp][] = [
        ["not an object", null, /not an object/],
        ["another schema", { schema: "x", entries: [] }, /schema must be/],
        ["no list", { schema: WRAPPER_REGISTRY_SCHEMA, entries: {} }, /entries must be a list/],
        [
          "a numeric chain id",
          { schema: WRAPPER_REGISTRY_SCHEMA, entries: [{ ...entry, chainId: 1 }] },
          /decimal string/,
        ],
        [
          "a zero-led chain id",
          { schema: WRAPPER_REGISTRY_SCHEMA, entries: [{ ...entry, chainId: "01" }] },
          /decimal string/,
        ],
        [
          "a malformed address",
          { schema: WRAPPER_REGISTRY_SCHEMA, entries: [{ ...entry, address: "0x12" }] },
          /must be an address/,
        ],
        [
          "a duplicate",
          { schema: WRAPPER_REGISTRY_SCHEMA, entries: [entry, { ...entry, address: entry.address.toLowerCase() }] },
          /listed twice/,
        ],
      ];
      for (const [label, doc, rule] of cases) expect(wrapperRegistryErrors(doc).join("\n"), label).to.match(rule);
    });
  });

  describe("measuring a verifier from the chain", function () {
    it("profiles a haltable wrapper, a non-haltable SP1 verifier, the mock and an account without code", async function () {
      const p = await profileVerifier(ethers.provider, await haltable.getAddress());
      expect(p).to.include({
        hasCode: true,
        genuineWrapper: true,
        algorithmId: ZK_ALGORITHM_ID,
        sp1Verifier: await sp1.getAddress(),
        programVKey: VKEY_A,
        haltPrincipal: haltPrincipal.address,
        halted: false,
      });
      expect([isOnSp1Path(p), isHaltable(p)]).to.deep.equal([true, true]);
      const u = await profileVerifier(ethers.provider, await unhaltable.getAddress());
      expect([isOnSp1Path(u), isHaltable(u), u.haltPrincipal, u.halted, u.genuineWrapper]).to.deep.equal([
        true,
        false,
        null,
        null,
        false,
      ]);
      const m = await profileVerifier(ethers.provider, await mock.getAddress());
      expect([isOnSp1Path(m), isHaltable(m), m.identity, m.genuineWrapper]).to.deep.equal([false, false, null, false]);
      const eoa = await profileVerifier(ethers.provider, stranger.address);
      expect([eoa.hasCode, isOnSp1Path(eoa), eoa.genuineWrapper]).to.deep.equal([false, false, false]);
      await haltable.connect(haltPrincipal).halt();
      expect((await profileVerifier(ethers.provider, await haltable.getAddress())).halted).to.equal(true);
    });

    it("reads a malformed answer as no answer, as the on-chain guard does (positive control: well-formed answers are read)", async function () {
      const m = await (await ethers.getContractFactory("MisbehavingVerifierMock")).deploy();
      const sel = (signature: string) => ethers.id(signature).slice(0, 10);
      const [RETURN, REVERT_WITH_WORD, RETURN_SHORT] = [1, 2, 3];
      await m.program(sel("HALT_PRINCIPAL()"), RETURN, ethers.toBeHex(BigInt(admin.address) | (1n << 200n), 32));
      await m.program(sel("halted()"), RETURN_SHORT, ethers.toBeHex(1n << 248n, 32));
      await m.program(sel("SP1_VERIFIER()"), REVERT_WITH_WORD, ethers.zeroPadValue(await sp1.getAddress(), 32));
      await m.program(sel("PROGRAM_VKEY()"), RETURN, VKEY_A);
      const p = await profileVerifier(ethers.provider, await m.getAddress());
      expect([p.haltPrincipal, p.halted, p.sp1Verifier, p.sp1VerifierCodeKeccak, p.identity]).to.deep.equal([
        null,
        null,
        null,
        null,
        null,
      ]);
      expect(p.programVKey).to.equal(VKEY_A);
      // A zero halt principal names no one; an SP1 verifier without code has no code hash, so no identity.
      await m.program(sel("HALT_PRINCIPAL()"), RETURN, ethers.ZeroHash);
      await m.program(sel("SP1_VERIFIER()"), RETURN, ethers.zeroPadValue(stranger.address, 32));
      const z = await profileVerifier(ethers.provider, await m.getAddress());
      expect([z.haltPrincipal, z.sp1Verifier, z.sp1VerifierCodeKeccak, z.identity]).to.deep.equal([
        null,
        stranger.address,
        null,
        null,
      ]);
      await m.program(sel("HALT_PRINCIPAL()"), RETURN, ethers.zeroPadValue(admin.address, 32));
      await m.program(sel("halted()"), RETURN, ethers.zeroPadValue("0x01", 32));
      await m.program(sel("SP1_VERIFIER()"), RETURN, ethers.zeroPadValue(await sp1.getAddress(), 32));
      const q = await profileVerifier(ethers.provider, await m.getAddress());
      expect([q.haltPrincipal, q.halted, q.sp1Verifier]).to.deep.equal([admin.address, true, await sp1.getAddress()]);
      expect(q.identity).to.equal((await profileVerifier(ethers.provider, await haltable.getAddress())).identity);
      // Any non-zero halted() word reads as halted, as on chain.
      await m.program(sel("halted()"), RETURN, ethers.zeroPadValue("0x02", 32));
      expect((await profileVerifier(ethers.provider, await m.getAddress())).halted).to.equal(true);
    });

    it("computes the same identity the on-chain guard records and stores", async function () {
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await haltable.getAddress());
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      const identity = (await profileVerifier(ethers.provider, await haltable.getAddress())).identity!;
      expect(await vault.pqVerifierIdentity()).to.equal(identity);
      await haltable.connect(haltPrincipal).halt();
      await vault.proposePQVerifier(await recovery.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await vault.applyPQVerifierUpdate();
      const recoveryIdentity = (await profileVerifier(ethers.provider, await recovery.getAddress())).identity!;
      expect(await vault.haltedVerifierIdentities(identity)).to.equal(true);
      expect(await vault.haltedVerifierIdentities(recoveryIdentity)).to.equal(false);
      expect(await vault.pqVerifierIdentity()).to.equal(recoveryIdentity);
    });
  });

  describe("a target must be a ZKMLDSAVerifier compiled from this tree (the review's look-alike)", function () {
    it("compares runtime code with the artifact, immutables masked and metadata excluded", async function () {
      const artifact = readWrapperArtifact();
      const code = await ethers.provider.getCode(await haltable.getAddress());
      expect(matchesWrapperArtifact(code, artifact), "a deployed wrapper").to.equal(true);
      // Other immutables (another verifier, vkey and halt principal) are the same code.
      const other = await deployWrapper(await deploySp1(), VKEY_B, otherHaltPrincipal.address);
      expect(matchesWrapperArtifact(await ethers.provider.getCode(await other.getAddress()), artifact)).to.equal(true);
      // The metadata trailer (the source hash) is not compared...
      const bytes = ethers.getBytes(code);
      const trailer = Uint8Array.from(bytes);
      // Inside the IPFS source hash: the CBOR map starts a2 64 "ipfs" 58 22, so its payload begins 8 bytes in.
      const cborStart = bytes.length - 2 - ((bytes[bytes.length - 2] << 8) | bytes[bytes.length - 1]);
      trailer[cborStart + 12] ^= 0xff;
      expect(matchesWrapperArtifact(ethers.hexlify(trailer), artifact), "metadata byte changed").to.equal(true);
      // ...but every executable byte is.
      const executable = Uint8Array.from(bytes);
      executable[5] ^= 0x01;
      expect(matchesWrapperArtifact(ethers.hexlify(executable), artifact), "code byte changed").to.equal(false);
      for (const notWrapper of [
        await ethers.provider.getCode(await unhaltable.getAddress()),
        await ethers.provider.getCode(await mock.getAddress()),
        "0x",
        ethers.hexlify(bytes.slice(0, -1)),
      ]) {
        expect(matchesWrapperArtifact(notWrapper, artifact)).to.equal(false);
      }
    });

    it("refuses a look-alike that reports the designated identity, a halt principal and ACTIVE; admits the genuine wrapper", async function () {
      const lookalike = await (await ethers.getContractFactory("MisbehavingVerifierMock")).deploy();
      const sel = (signature: string) => ethers.id(signature).slice(0, 10);
      await lookalike.program(sel("HALT_PRINCIPAL()"), 1, ethers.zeroPadValue(haltPrincipal.address, 32));
      await lookalike.program(sel("halted()"), 1, ethers.ZeroHash);
      await lookalike.program(sel("SP1_VERIFIER()"), 1, ethers.zeroPadValue(await sp1.getAddress(), 32));
      await lookalike.program(sel("PROGRAM_VKEY()"), 1, VKEY_A);
      const fake = await profileVerifier(ethers.provider, await lookalike.getAddress());
      expect(isHaltable(fake)).to.equal(true);
      expect(bindingRefusals(request(fake, { chainId: LOCAL, allowMockSp1: true })).join("\n")).to.match(
        /not a ZKMLDSAVerifier compiled from this tree/,
      );
      const genuine = await profileVerifier(ethers.provider, await haltable.getAddress());
      expect(bindingRefusals(request(genuine, { chainId: LOCAL, allowMockSp1: true }))).to.deep.equal([]);
    });
  });

  describe("EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER", function () {
    it("without the local override, deployment tooling refuses a consumer in scope an unregistered, undesignated wrapper", async function () {
      await assert.rejects(
        checkDeploymentBinding(ethers.provider, "WalletWallVault", await haltable.getAddress(), admin.address, {
          allowMockSp1: false,
        }),
        /not in the WalletWall wrapper registry for chain 31337.*matches no designation/s,
      );
    });

    it("deployment tooling refuses WalletWallMultiSigVault a haltable wrapper, and the consumers in scope are not refused it", async function () {
      await assert.rejects(
        checkDeploymentBinding(
          ethers.provider,
          "WalletWallMultiSigVault",
          await haltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /WalletWallMultiSigVault waits outside the halt for TD2-MULTISIG-ROTATION.*haltable wrapper would lock its funds/s,
      );
      // Positive controls: the same wrapper for each consumer in scope that is deployed bound to a verifier...
      for (const consumer of ["WalletWallVault", "StablecoinVaultSimulator"] as const) {
        await checkDeploymentBinding(ethers.provider, consumer, await haltable.getAddress(), admin.address, MOCK_OK);
      }
      // ...and the multisig vault itself, off the SP1 path (the mock verifier).
      await checkDeploymentBinding(
        ethers.provider,
        "WalletWallMultiSigVault",
        await mock.getAddress(),
        admin.address,
        MOCK_OK,
      );
    });

    it("refuses the multisig vault any part of the SP1 path, a non-haltable SP1 verifier included (its interim is NOT_BOUND_TO_THE_SP1_PATH)", async function () {
      await assert.rejects(
        checkDeploymentBinding(
          ethers.provider,
          "WalletWallMultiSigVault",
          await unhaltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /may be bound to no part of the SP1 path/,
      );
    });

    it("rotation tooling refuses to rotate a deployed multisig vault onto a haltable wrapper; a vault in scope may be", async function () {
      const multisig = await (
        await ethers.getContractFactory("WalletWallMultiSigVault", admin)
      ).deploy(await mock.getAddress());
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await multisig.getAddress(),
          await haltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /WalletWallMultiSigVault waits outside the halt/,
      );
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      const ok = await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await haltable.getAddress(),
        admin.address,
        MOCK_OK,
      );
      expect(ok.consumer).to.equal("WalletWallVault");
    });

    it("the scripts that bind a consumer go through the gate, naming the consumer they deploy", function () {
      const source = (rel: string) => readFileSync(resolve(rel), "utf8");
      // deploy.ts gates the vault itself; deploy-multisig.ts runs deployMultisigVault, which gates the multisig vault
      // (exercised in test/Sp1Td2DeploymentTooling.test.ts). Each gate runs before its consumer is deployed.
      // Each call passes the account that deploys (or proposes) as the signer and the operator's ALLOW_MOCK_SP1 flag
      // as the override, nothing else: a forced override or another signer would skip rules on a local chain.
      expect(source("scripts/deploy.ts")).to.match(
        /checkDeploymentBinding\(ethers\.provider, "WalletWallVault", pqVerifierAddress, await deployer\.getAddress\(\), \{\s*allowMockSp1: process\.env\.ALLOW_MOCK_SP1 === "true",\s*\}\);/,
      );
      expect(source("scripts/deploy.ts")).to.match(/getContractFactory\("WalletWallVault", deployer\)/);
      expect(source("scripts/deploy-multisig.ts")).to.match(
        /deployMultisigVault\(ethers, deployer, \{\s*pqcVerifierAddress: process\.env\.PQC_VERIFIER_ADDRESS,\s*allowMockSp1: process\.env\.ALLOW_MOCK_SP1 === "true",\s*\}\);/,
      );
      expect(source("scripts/deploy-multisig.ts")).to.not.match(/getContractFactory\(/);
      const lib = source("scripts/lib/deployment-guards.ts");
      expect(lib).to.match(/checkDeploymentBinding\(\s*ethers\.provider,\s*"WalletWallMultiSigVault",/);
      for (const [rel, factory] of [
        ["scripts/deploy.ts", '"WalletWallVault"'],
        ["scripts/lib/deployment-guards.ts", '"WalletWallMultiSigVault"'],
      ]) {
        const text = source(rel);
        expect(text.indexOf("checkDeploymentBinding("), rel).to.be.lessThan(
          text.indexOf(`getContractFactory(${factory}`),
        );
      }
      const propose = source("scripts/propose-verifier-update.ts");
      expect(propose).to.match(
        /checkRotationBinding\(\s*ethers\.provider,\s*vaultAddress,\s*newVerifierAddress,\s*await proposer\.getAddress\(\),\s*\{ allowMockSp1: process\.env\.ALLOW_MOCK_SP1 === "true" \},\s*\);/,
      );
      // The proposer it checks is the account that sends the proposal: the first signer, which getContractAt uses.
      expect(propose).to.match(/const \[proposer\] = await ethers\.getSigners\(\);/);
      expect(propose).to.match(/const vault = await ethers\.getContractAt\("WalletWallVault", vaultAddress\);/);
      expect(propose.indexOf("checkRotationBinding(")).to.be.lessThan(propose.indexOf(".proposePQVerifier("));
      // The multisig script checks the chain before it deploys anything.
      const multisig = source("scripts/deploy-multisig.ts");
      expect(multisig).to.match(/assertDeployableChain\(connection\.networkName,/);
      expect(multisig.indexOf("assertDeployableChain(")).to.be.lessThan(multisig.indexOf("deployMultisigVault("));
      // The wrapper deployment passes the resolved halt principal, and nothing else, as the third argument.
      const zk = source("scripts/deploy-zk-verifier.ts");
      // ...resolved from the operator's HALT_PRINCIPAL_ADDRESS, defaulting only on a local chain and only to the second
      // local account, never the deployer.
      expect(zk).to.match(
        /const haltPrincipal = resolveHaltPrincipal\(\s*process\.env\.HALT_PRINCIPAL_ADDRESS,\s*isLocalNetwork,\s*localHaltPrincipal\?\.address,\s*\);/,
      );
      expect(zk).to.match(
        /const isLocalNetwork = chainNetwork\.chainId === 31337n \|\| chainNetwork\.chainId === 1337n;/,
      );
      expect(zk).to.match(/const \[deployer, localHaltPrincipal\] = await ethers\.getSigners\(\);/);
      expect(zk).to.match(/ZKMLDSAVerifier\.deploy\(sp1VerifierAddress, programVKey, haltPrincipal\)/);
    });
  });

  describe("TD1-N12: recovery-target gating by process", function () {
    let realVerifier: string;
    let designated: VerifierProfile;
    let mockSp1Wrapper: VerifierProfile;

    beforeEach(async function () {
      // A wrapper over the real SP1Verifier v6.1.0 bytes (CREATE2-authenticated in SP1-TD1) with the designated vkey.
      const receipt = await (await admin.sendTransaction({ data: BYTECODE.deployments["v6.1.0"].initcode })).wait();
      realVerifier = receipt.contractAddress;
      const real = await deployWrapper(
        { getAddress: async () => realVerifier },
        TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey,
        haltPrincipal.address,
      );
      designated = await profileVerifier(ethers.provider, await real.getAddress());
      mockSp1Wrapper = await profileVerifier(ethers.provider, await haltable.getAddress());
    });

    it("positive control: a registered wrapper over the designated verifier code with the designated vkey passes on a non-local chain", function () {
      expect(designated.sp1VerifierCodeKeccak).to.equal(TD1.trustTarget.codeKeccak);
      expect(designated.genuineWrapper).to.equal(true);
      expect(bindingRefusals(registeredRequest(designated))).to.deep.equal([]);
    });

    it("refuses another SP1 verifier code or another PROGRAM_VKEY on a non-local chain, and grants no override there", function () {
      expect(bindingRefusals(registeredRequest(mockSp1Wrapper)).join("\n")).to.match(/matches no designation/);
      const otherVKey = { ...designated, programVKey: VKEY_B };
      expect(bindingRefusals(registeredRequest(otherVKey)).join("\n")).to.match(/matches no designation/);
      expect(bindingRefusals(registeredRequest(mockSp1Wrapper, { allowMockSp1: true })).join("\n")).to.match(
        /no override exists on chain 11155111/,
      );
      // The override works only where it is meant to: a local chain.
      expect(bindingRefusals(request(mockSp1Wrapper, { chainId: LOCAL, allowMockSp1: true }))).to.deep.equal([]);
      expect(
        bindingRefusals(registeredRequest(mockSp1Wrapper, { chainId: LOCAL })).length,
        "no flag, no mock",
      ).to.be.greaterThan(0);
    });

    it("refuses a halted target, a recorded halted identity, a fresh deployment of the current halted identity, and a signer that can halt", function () {
      const cases: [string, BindingRequest, RegExp][] = [
        ["halted target", registeredRequest({ ...designated, halted: true }), /is HALTED/],
        [
          "recorded halted identity",
          registeredRequest(designated, { targetIdentityRecordedHalted: true }),
          /halted wrapper .* recorded/,
        ],
        [
          "fresh deployment of the identity the halted current verifier was installed with",
          registeredRequest(designated, {
            current: { ...designated, address: stranger.address, halted: true },
            currentIdentity: designated.identity,
          }),
          /fresh deployment of the halted identity/,
        ],
        [
          "signer is the target's halt principal",
          registeredRequest(designated, { signer: haltPrincipal.address }),
          /halt principal never governs/,
        ],
        [
          "signer is the target's halt principal, spelled in lower case",
          registeredRequest(designated, { signer: haltPrincipal.address.toLowerCase() }),
          /halt principal never governs/,
        ],
        [
          "signer can halt the current verifier",
          registeredRequest(designated, { current: { ...mockSp1Wrapper, haltPrincipal: admin.address } }),
          /can halt the current verifier/,
        ],
        [
          "signer can halt the current verifier, spelled in lower case",
          registeredRequest(designated, {
            signer: admin.address.toLowerCase(),
            current: { ...mockSp1Wrapper, haltPrincipal: admin.address },
          }),
          /can halt the current verifier/,
        ],
      ];
      for (const [label, req, refusal] of cases) expect(bindingRefusals(req).join("\n"), label).to.match(refusal);
      // Positive controls: an ACTIVE current verifier of the same stored identity, and a halted current verifier
      // installed with another identity (whatever it reports now), do not disqualify the target.
      expect(
        bindingRefusals(
          registeredRequest(designated, {
            current: { ...designated, address: stranger.address },
            currentIdentity: designated.identity,
          }),
        ),
      ).to.deep.equal([]);
      expect(
        bindingRefusals(
          registeredRequest(designated, {
            current: { ...designated, address: stranger.address, halted: true },
            currentIdentity: mockSp1Wrapper.identity,
          }),
        ),
      ).to.deep.equal([]);
    });

    it("refuses an SP1-path verifier that cannot be halted for a consumer in scope, and any consumer the scope does not name", function () {
      const u = { ...designated, haltPrincipal: null, halted: null };
      expect(bindingRefusals(registeredRequest(u)).join("\n")).to.match(
        /not haltable: the halt would not reach WalletWallVault/,
      );
      expect(bindingRefusals(registeredRequest(designated, { consumer: "SomeOtherVault" })).join("\n")).to.match(
        /not a consumer the halt's scope names/,
      );
    });

    it("refuses a target without code; a registered designated wrapper passes on a local chain without any override", function () {
      expect(bindingRefusals(registeredRequest({ ...designated, hasCode: false })).join("\n")).to.match(/has no code/);
      expect(bindingRefusals(registeredRequest(designated, { chainId: LOCAL }))).to.deep.equal([]);
    });

    it("checks the code hash designated for the chain, falling back to the designation's own only where the chain has none", function () {
      const other = `0x${"ab".repeat(32)}`;
      const [td1] = readDesignations();
      const designations: Designation[] = [
        { ...td1, sp1VerifierCodeKeccakByChain: { ...td1.sp1VerifierCodeKeccakByChain, "11155111": other } },
      ];
      expect(
        bindingRefusals(registeredRequest({ ...designated, sp1VerifierCodeKeccak: other }, { designations })),
      ).to.deep.equal([]);
      expect(bindingRefusals(registeredRequest(designated, { designations })).join("\n")).to.match(
        /matches no designation/,
      );
      // A chain the designation does not list falls back to its trust target's code hash.
      expect(bindingRefusals(registeredRequest(designated, { designations, chainId: 10_000n }))).to.deep.equal([]);
    });

    it("anything that answers one part of the SP1 surface is on the SP1 path, and a wrapper needs both halves of the halt surface", function () {
      const bare: VerifierProfile = {
        address: stranger.address,
        hasCode: true,
        genuineWrapper: false,
        algorithmId: null,
        sp1Verifier: null,
        sp1VerifierCodeKeccak: null,
        programVKey: null,
        haltPrincipal: null,
        halted: null,
        identity: null,
      };
      expect(isOnSp1Path(bare), "positive control: nothing answered").to.equal(false);
      for (const part of [
        { algorithmId: ZK_ALGORITHM_ID },
        { sp1Verifier: stranger.address },
        { programVKey: VKEY_A },
        { haltPrincipal: haltPrincipal.address },
        { halted: false },
      ]) {
        const p = { ...bare, ...part };
        expect(isOnSp1Path(p), JSON.stringify(part)).to.equal(true);
        expect(bindingRefusals(request(p, { consumer: "WalletWallMultiSigVault" })).join("\n")).to.match(
          /may be bound to no part of the SP1 path/,
        );
      }
      expect(isHaltable({ ...bare, haltPrincipal: haltPrincipal.address })).to.equal(false);
      expect(isHaltable({ ...bare, halted: false })).to.equal(false);
      expect(isHaltable({ ...bare, haltPrincipal: haltPrincipal.address, halted: false })).to.equal(true);
      for (const half of [{ halted: null }, { haltPrincipal: null }]) {
        expect(
          bindingRefusals(registeredRequest({ ...designated, ...half })).join("\n"),
          JSON.stringify(half),
        ).to.match(/not haltable/);
      }
    });

    it("end to end: after a vault leaves a halted wrapper, the tooling refuses that identity from the record the vault keeps", async function () {
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await haltable.getAddress());
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      await haltable.connect(haltPrincipal).halt();
      await vault.proposePQVerifier(await recovery.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await vault.applyPQVerifierUpdate();
      // The current wrapper is ACTIVE now; only the recorded identity can refuse the redeploy.
      const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await vault.getAddress(),
          await fresh.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /has the identity of a halted wrapper WalletWallVault recorded/,
      );
      const independent = await deployWrapper(await deploySp1(), VKEY_B, haltPrincipal.address);
      await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await independent.getAddress(),
        admin.address,
        MOCK_OK,
      );
    });

    it("refuses an impostor that reports a consumer's EIP-712 domain but has no verifier", async function () {
      const impostor = await (await ethers.getContractFactory("Eip712DomainOnlyMock")).deploy("WalletWallVault");
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await impostor.getAddress(),
          await haltable.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /reports no pqVerifier/,
      );
    });

    it("a verifier off the SP1 path (the mock) is outside these rules for the consumers in scope", async function () {
      const m = await profileVerifier(ethers.provider, await mock.getAddress());
      expect(bindingRefusals(request(m))).to.deep.equal([]);
      expect(bindingRefusals(request(m, { consumer: "StablecoinVaultSimulator" }))).to.deep.equal([]);
    });

    it("HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET, process side: on a live vault the tooling refuses a fresh deployment of its halted identity, as the chain does", async function () {
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await haltable.getAddress());
      await haltable.connect(haltPrincipal).halt();
      const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      await assert.rejects(
        checkRotationBinding(
          ethers.provider,
          await vault.getAddress(),
          await fresh.getAddress(),
          admin.address,
          MOCK_OK,
        ),
        /fresh deployment of the halted identity/,
      );
      await expect(vault.proposePQVerifier(await fresh.getAddress())).to.be.revertedWithCustomError(
        vault,
        "HaltedVerifierIdentity",
      );
      // Positive control: an independent identity passes both.
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await recovery.getAddress(),
        admin.address,
        MOCK_OK,
      );
      await vault.proposePQVerifier(await recovery.getAddress());
    });

    it("HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET, process side: while excluded, the multisig vault is refused every SP1 target, a fresh deployment of a halted identity included", async function () {
      const multisig = await (
        await ethers.getContractFactory("WalletWallMultiSigVault", admin)
      ).deploy(await mock.getAddress());
      await haltable.connect(haltPrincipal).halt();
      const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      const recovery = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
      for (const target of [haltable, fresh, recovery]) {
        await assert.rejects(
          checkRotationBinding(
            ethers.provider,
            await multisig.getAddress(),
            await target.getAddress(),
            admin.address,
            MOCK_OK,
          ),
          /WalletWallMultiSigVault waits outside the halt/,
        );
      }
      // Positive control: the gate's rules admit an off-path verifier for it (the rotation script itself proposes ZK
      // targets only, so it cannot rotate the multisig vault while it is excluded).
      const otherMock = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
      const profile = await profileVerifier(ethers.provider, await otherMock.getAddress());
      expect(bindingRefusals(request(profile, { consumer: "WalletWallMultiSigVault" }))).to.deep.equal([]);
    });
  });

  describe("the wrapper registry: one halt reaches every consumer, and a halt is seen by every consumer", function () {
    it("refuses an unregistered wrapper off a local chain, and a second ACTIVE registered wrapper of the same identity", async function () {
      const target = await profileVerifier(ethers.provider, await haltable.getAddress());
      const designation: Designation = {
        source: "a test designation of the mock program",
        sp1VerifierCodeKeccak: target.sp1VerifierCodeKeccak!,
        sp1VerifierCodeKeccakByChain: {},
        programVKey: VKEY_A,
      };
      const base = { chainId: LOCAL, designations: [designation] };
      expect(bindingRefusals(request(target, { ...base, registered: [target] })), "positive control").to.deep.equal([]);
      expect(bindingRefusals(request(target, { ...base, registered: [] })).join("\n")).to.match(
        /not in the WalletWall wrapper registry for chain 31337/,
      );
      const twin = await profileVerifier(
        ethers.provider,
        await (await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address)).getAddress(),
      );
      expect(bindingRefusals(request(target, { ...base, registered: [target, twin] })).join("\n")).to.match(
        /another ACTIVE registered wrapper of .* identity: one halt call must reach every consumer/,
      );
    });

    it("refuses an identity halted at any registered wrapper, for every consumer and even under the local override", async function () {
      // Consumer A used w1 and left it while it was ACTIVE; w1 was halted later. A consumer that never used w1 is
      // refused a fresh deployment of its identity all the same, because the registry shows the halt.
      const w1 = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
      await w1.connect(haltPrincipal).halt();
      const halted = await profileVerifier(ethers.provider, await w1.getAddress());
      const freshA = await profileVerifier(ethers.provider, await haltable.getAddress()); // identity A, ACTIVE
      expect(freshA.identity).to.equal(halted.identity);
      expect(
        bindingRefusals(request(freshA, { chainId: LOCAL, allowMockSp1: true, registered: [halted] })).join("\n"),
      ).to.match(/has the identity of registered wrapper .*, which is HALTED/);
      const otherB = await profileVerifier(
        ethers.provider,
        await (await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address)).getAddress(),
      );
      expect(
        bindingRefusals(request(otherB, { chainId: LOCAL, allowMockSp1: true, registered: [halted] })),
        "positive control: another identity",
      ).to.deep.equal([]);
      // End to end through the tooling, with the registry naming the halted wrapper.
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      await assert.rejects(
        checkRotationBinding(ethers.provider, await vault.getAddress(), await haltable.getAddress(), admin.address, {
          ...MOCK_OK,
          registry: [await w1.getAddress()],
        }),
        /which is HALTED/,
      );
      await assert.rejects(
        checkDeploymentBinding(ethers.provider, "WalletWallVault", await haltable.getAddress(), admin.address, {
          ...MOCK_OK,
          registry: [await w1.getAddress()],
        }),
        /which is HALTED/,
      );
    });

    it("tells an ACTIVE twin from a HALTED one: only an ACTIVE twin breaks 'one halt reaches every consumer'", async function () {
      const target = await profileVerifier(ethers.provider, await haltable.getAddress());
      const designation: Designation = {
        source: "a test designation of the mock program",
        sp1VerifierCodeKeccak: target.sp1VerifierCodeKeccak!,
        sp1VerifierCodeKeccakByChain: {},
        programVKey: VKEY_A,
      };
      const twinWrapper = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
      const activeTwin = await profileVerifier(ethers.provider, await twinWrapper.getAddress());
      // Under the local override an ACTIVE twin is no refusal at all (registration rules are off there).
      expect(
        bindingRefusals(request(target, { chainId: LOCAL, allowMockSp1: true, registered: [target, activeTwin] })),
      ).to.deep.equal([]);
      await twinWrapper.connect(otherHaltPrincipal).halt();
      const haltedTwin = await profileVerifier(ethers.provider, await twinWrapper.getAddress());
      const refusals = bindingRefusals(
        request(target, { chainId: LOCAL, designations: [designation], registered: [target, haltedTwin] }),
      ).join("\n");
      expect(refusals).to.match(/which is HALTED/);
      expect(refusals, "a halted twin is not an ACTIVE one").to.not.match(/another ACTIVE registered wrapper/);
    });

    it("the tooling entry points pass the registry and designations they are given through to the gate", async function () {
      const target = await profileVerifier(ethers.provider, await haltable.getAddress());
      const designation: Designation = {
        source: "a test designation of the mock program",
        sp1VerifierCodeKeccak: target.sp1VerifierCodeKeccak!,
        sp1VerifierCodeKeccakByChain: {},
        programVKey: VKEY_A,
      };
      const options = { allowMockSp1: false, registry: [await haltable.getAddress()], designations: [designation] };
      await checkDeploymentBinding(
        ethers.provider,
        "WalletWallVault",
        await haltable.getAddress(),
        admin.address,
        options,
      );
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      await checkRotationBinding(
        ethers.provider,
        await vault.getAddress(),
        await haltable.getAddress(),
        admin.address,
        options,
      );
      // Without the designation the same binding is refused.
      await assert.rejects(
        checkDeploymentBinding(ethers.provider, "WalletWallVault", await haltable.getAddress(), admin.address, {
          ...options,
          designations: undefined,
        }),
        /matches no designation/,
      );
    });

    it("reads the registry file for the chain it is asked about, and refuses a malformed one", function () {
      const dir = mkdtempSync(join(tmpdir(), "td2-registry-"));
      try {
        mkdirSync(join(dir, "evidence/zk/sp1-td2"), { recursive: true });
        const write = (doc: unknown) =>
          writeFileSync(join(dir, "evidence/zk/sp1-td2/wrapper-registry.json"), JSON.stringify(doc));
        write({
          schema: WRAPPER_REGISTRY_SCHEMA,
          entries: [
            { chainId: "11155111", address: stranger.address.toLowerCase() },
            { chainId: "84532", address: admin.address },
          ],
        });
        expect(readWrapperRegistry(SEPOLIA, dir)).to.deep.equal([stranger.address]);
        expect(readWrapperRegistry(84532n, dir)).to.deep.equal([admin.address]);
        expect(readWrapperRegistry(1n, dir)).to.deep.equal([]);
        write({ schema: WRAPPER_REGISTRY_SCHEMA, entries: [{ chainId: "1", address: "0x12" }] });
        assert.throws(() => readWrapperRegistry(1n, dir), /malformed evidence\/zk\/sp1-td2\/wrapper-registry\.json/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("refuses everything while a registry entry is not a genuine wrapper", async function () {
      const target = await profileVerifier(ethers.provider, await haltable.getAddress());
      const bogus = await profileVerifier(ethers.provider, await unhaltable.getAddress());
      expect(
        bindingRefusals(request(target, { chainId: LOCAL, allowMockSp1: true, registered: [bogus] })).join("\n"),
      ).to.match(/registered wrapper .* is not a ZKMLDSAVerifier compiled from this tree/);
    });
  });

  describe("every measurement fails closed (the review's R2-2: an RPC that does not answer is not 'no answer')", function () {
    const selectorOf = (signature: string) => ethers.id(signature).slice(0, 10);
    const rpcError = (message: string, code?: number) =>
      Object.assign(new Error(message), code === undefined ? {} : { code });
    /** ethers.provider, except that an eth_call of `signature` on `to` fails with `error`. */
    const flaky = (to: string, signature: string, error: unknown) =>
      new Proxy(ethers.provider, {
        get(target, prop) {
          if (prop === "call") {
            return async (tx: { to: string; data: string }) => {
              if (tx.to.toLowerCase() === to.toLowerCase() && tx.data.startsWith(selectorOf(signature))) throw error;
              return target.call(tx);
            };
          }
          const value = Reflect.get(target, prop, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });

    it("only the chain's own answer reads as no answer: a revert or running out of gas, never an RPC failure", function () {
      const answers: [string, unknown][] = [
        ["EIP-1474 revert", rpcError("execution reverted", 3)],
        ["EIP-1474 revert, any message", rpcError("Transaction reverted without a reason string", 3)],
        ["ethers' own providers", { code: "CALL_EXCEPTION", message: "missing revert data" }],
        ["out of gas (EDR, geth)", rpcError("Transaction ran out of gas", -32000)],
        ["revert without data (geth)", rpcError("execution reverted", -32000)],
        ["gas cap", rpcError("gas required exceeds allowance (30000000)", -32000)],
        ["invalid opcode", rpcError("invalid opcode: INVALID", -32000)],
        ["invalid jump", rpcError("invalid jump destination", -32000)],
        ["stack underflow", rpcError("stack underflow (0 <=> 1)", -32000)],
        ["stack overflow", rpcError("stack limit reached 1024 (1023): stack overflow", -32000)],
        ["Nethermind", rpcError("VM execution error.", -32015)],
        ["internal error that says it reverted", rpcError("execution reverted: nope", -32603)],
      ];
      for (const [label, error] of answers) expect(isExecutionFailure(error), label).to.equal(true);
      const noAnswers: [string, unknown][] = [
        ["rate limit (Hardhat's LimitExceededError)", rpcError("Too Many Requests", -32005)],
        ["rate limit that mentions a revert", rpcError("execution reverted too often: rate limited", -32005)],
        ["unknown transport failure (Hardhat's UnknownError)", rpcError("fetch failed", -1)],
        ["refused connection (a HardhatError, no JSON-RPC code)", rpcError("connect ECONNREFUSED 127.0.0.1:8545")],
        ["a node that lost the state", rpcError("missing trie node", -32000)],
        ["a node behind", rpcError("header not found", -32000)],
        ["a bare internal error", rpcError("Internal error", -32603)],
        ["a server error without a message", { code: -32000 }],
        ["a server error with a non-text message", { code: -32000, message: 42 }],
        ["an HTTP status as a code", rpcError("Too Many Requests", 429)],
        ["null", null],
        ["a string", "execution reverted"],
      ];
      for (const [label, error] of noAnswers) expect(isExecutionFailure(error), label).to.equal(false);
    });

    it("the review's scenario: a registered wrapper's halt the RPC did not report stops the gate instead of disappearing", async function () {
      const w1 = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
      await w1.connect(haltPrincipal).halt();
      const fresh = await haltable.getAddress(); // identity A, ACTIVE
      const options = { ...MOCK_OK, registry: [await w1.getAddress()] };
      // Positive control: with a provider that answers, the fresh deployment of the halted identity is refused.
      await assert.rejects(
        checkDeploymentBinding(ethers.provider, "WalletWallVault", fresh, admin.address, options),
        /which is HALTED/,
      );
      const RATE_LIMITED = rpcError("Too Many Requests", -32005);
      for (const signature of ["halted()", "SP1_VERIFIER()", "PROGRAM_VKEY()"]) {
        await assert.rejects(
          checkDeploymentBinding(
            flaky(await w1.getAddress(), signature, RATE_LIMITED),
            "WalletWallVault",
            fresh,
            admin.address,
            options,
          ),
          /got no answer from the chain/,
          signature,
        );
      }
      // The target and the current verifier fail closed the same way, whatever the transport failure looks like.
      await assert.rejects(
        checkDeploymentBinding(
          flaky(fresh, "halted()", rpcError("connect ECONNREFUSED")),
          "WalletWallVault",
          fresh,
          admin.address,
          MOCK_OK,
        ),
        /got no answer from the chain/,
      );
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      await assert.rejects(
        checkRotationBinding(
          flaky(await mock.getAddress(), "halted()", RATE_LIMITED),
          await vault.getAddress(),
          fresh,
          admin.address,
          MOCK_OK,
        ),
        /got no answer from the chain/,
      );
      // A revert IS the chain's answer: it reads as no answer, and the genuine wrapper that gave it is refused
      // because it can no longer be measured completely.
      await assert.rejects(
        checkDeploymentBinding(
          flaky(await w1.getAddress(), "halted()", rpcError("execution reverted", 3)),
          "WalletWallVault",
          fresh,
          admin.address,
          options,
        ),
        /registered wrapper .* could not be measured/,
      );
    });

    it("a genuine wrapper that cannot be measured completely is refused, never skipped", async function () {
      const target = await profileVerifier(ethers.provider, await haltable.getAddress());
      const local = { chainId: LOCAL, allowMockSp1: true };
      expect(bindingRefusals(request(target, { ...local, registered: [target] })), "positive control").to.deep.equal(
        [],
      );
      for (const missing of [{ halted: null }, { identity: null }, { haltPrincipal: null }]) {
        expect(
          bindingRefusals(request(target, { ...local, registered: [{ ...target, ...missing }] })).join("\n"),
          `registered ${JSON.stringify(missing)}`,
        ).to.match(/registered wrapper .* could not be measured/);
        expect(
          bindingRefusals(request(target, { ...local, current: { ...target, ...missing } })).join("\n"),
          `current ${JSON.stringify(missing)}`,
        ).to.match(/the current verifier .* could not be measured/);
      }
      // A target whose identity could not be measured (an SP1 verifier without code reads the same way).
      expect(
        bindingRefusals(request({ ...target, sp1VerifierCodeKeccak: null, identity: null }, local)).join("\n"),
      ).to.match(/the target .* could not be measured/);
      // A verifier that is not a genuine wrapper legitimately answers nothing (the mock): no refusal for that.
      const offPath = await profileVerifier(ethers.provider, await mock.getAddress());
      expect(offPath.halted).to.equal(null);
      expect(bindingRefusals(request(target, { ...local, current: offPath }))).to.deep.equal([]);
      // A genuine wrapper is on the SP1 path even if every reading of it failed.
      const silent = {
        ...target,
        algorithmId: null,
        sp1Verifier: null,
        sp1VerifierCodeKeccak: null,
        programVKey: null,
        haltPrincipal: null,
        halted: null,
        identity: null,
      };
      expect(isOnSp1Path(silent)).to.equal(true);
      expect(bindingRefusals(request(silent, local)).join("\n")).to.match(/not haltable/);
      expect(bindingRefusals(request(silent, { ...local, consumer: "WalletWallMultiSigVault" })).join("\n")).to.match(
        /may be bound to no part of the SP1 path/,
      );
    });
  });

  describe("recovery from a halt of the designated identity needs a successor designation", function () {
    it("off a local chain the gate admits no recovery target on SP1-TD1's designation alone, and admits a designated successor", async function () {
      // The designated wrapper is registered and HALTED (a v6.1.0 defect); the recovery wrapper runs fixed verifier
      // code with the same vkey, registered and ACTIVE.
      const receipt = await (await admin.sendTransaction({ data: BYTECODE.deployments["v6.1.0"].initcode })).wait();
      const designatedWrapper = await deployWrapper(
        { getAddress: async () => receipt.contractAddress },
        TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey,
        haltPrincipal.address,
      );
      await designatedWrapper.connect(haltPrincipal).halt();
      const fixedVerifier = await (await ethers.getContractFactory("MockSP1Verifier")).deploy();
      const recoveryWrapper = await deployWrapper(
        fixedVerifier,
        TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey,
        otherHaltPrincipal.address,
      );
      const halted = await profileVerifier(ethers.provider, await designatedWrapper.getAddress());
      const recovery = await profileVerifier(ethers.provider, await recoveryWrapper.getAddress());
      const registered = [halted, recovery];
      expect(bindingRefusals(request(recovery, { registered })).join("\n")).to.match(
        /matches no designation \(SP1-TD1 decision receipt\): a recovery identity needs a successor designation/,
      );
      const successor: Designation = {
        source: "a successor designation (the designation process's, simulated)",
        sp1VerifierCodeKeccak: recovery.sp1VerifierCodeKeccak!,
        sp1VerifierCodeKeccakByChain: {},
        programVKey: recovery.programVKey!,
      };
      expect(
        bindingRefusals(request(recovery, { registered, designations: [...readDesignations(), successor] })),
      ).to.deep.equal([]);
      // The halted identity stays refused even though SP1-TD1 designated it.
      const redeploy = await profileVerifier(
        ethers.provider,
        await (
          await deployWrapper(
            { getAddress: async () => receipt.contractAddress },
            TD1.decisions.PROGRAM_VKEY_DESIGNATION.vkey,
            otherHaltPrincipal.address,
          )
        ).getAddress(),
      );
      expect(bindingRefusals(request(redeploy, { registered: [...registered, redeploy] })).join("\n")).to.match(
        /which is HALTED/,
      );
    });
  });

  describe("identifying a consumer for rotation", function () {
    it("recognises the three rotating consumers by their EIP-712 domain and refuses anything else", async function () {
      const token = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await mock.getAddress());
      const sim = await (
        await ethers.getContractFactory("StablecoinVaultSimulator", admin)
      ).deploy(await token.getAddress(), await mock.getAddress());
      const multisig = await (
        await ethers.getContractFactory("WalletWallMultiSigVault", admin)
      ).deploy(await mock.getAddress());
      const bridge = await (await ethers.getContractFactory("PolicyControlBridge")).deploy(stranger.address);
      expect(await identifyConsumer(ethers.provider, await vault.getAddress())).to.equal("WalletWallVault");
      expect(await identifyConsumer(ethers.provider, await sim.getAddress())).to.equal("StablecoinVaultSimulator");
      expect(await identifyConsumer(ethers.provider, await multisig.getAddress())).to.equal("WalletWallMultiSigVault");
      for (const other of [await bridge.getAddress(), await mock.getAddress(), stranger.address]) {
        await assert.rejects(
          identifyConsumer(ethers.provider, other),
          /not a WalletWall consumer with a verifier rotation/,
        );
      }
    });
  });
});
