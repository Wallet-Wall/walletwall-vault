/**
 * SP1 implementation lane: the canonical PROGRAM_VKEY designation, generated from evidence
 * (docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD1 decided PINNED_VENDOR_BUILD and froze the designation contract:
 *   zkvm subject → canonical procedure (image by digest) → ELF sha256 → vkey (recomputed outside the build)
 *   → designation file → compile-time constant.
 * The first designation (mldsa65-withdrawal-d1) is DERIVED from SP1-TD1's evidence by the same derivations that
 * produced its receipt, as of the subject that evidence measured — never typed, never read from the working tree —
 * and validated by regenerating it. The expected values below are literals from the SP1-TD1 record (reviewed by the
 * owner), not outputs of the code under test.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import { deployPinnedSp1Verifier } from "./helpers/sp1PinnedVerifier";
import { TEST_HALT_PRINCIPAL } from "./helpers/zkVerifierHelpers";
import { readDecisionContext } from "../scripts/lib/sp1-td1-decision";
import {
  DESIGNATION_SCHEMA,
  SOUNDNESS_NOT_ESTABLISHED,
  compatibleDesignations,
  deriveInitialDesignation,
  designationSetErrors,
  initialDesignationDriftErrors,
  readDesignations,
  serializeDesignation,
  subjectFreshnessErrors,
  validateDesignationsInRepo,
  type ProgramDesignation,
} from "../scripts/lib/sp1-designation";
import { readWrapperBuilds } from "../scripts/lib/sp1-wrapper-build";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const ABI = ethers.AbiCoder.defaultAbiCoder();

/** From docs/SP1_TD1_Trust_Target_Program_Identity.md and evidence/zk/sp1-td1/decision-receipt.json. */
const TD1 = {
  elf: "2adddae753011fb08e30127e38befe99c0092c956e01bf4486ca81827a632d8a",
  elfBytes: 206504,
  vkey: "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc",
  image: "ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400",
  amd64Manifest: "sha256:7c1c8201de6f63e3f1fb9075bd9a67a4c5fc8c2d546d11a5ff71587bb51e6eb3",
  config: "sha256:aedac539617deeb11fb7fbac9270de9f8d0b021214eab05db672b2f0b181f796",
  guestTree: "f61fdc6c8785df742857574c5dbf47aa62283c49",
  hostTree: "30f72596c430974bf8113892bf41c26dce3629f3",
  manifest: "877fbcb28bd7f68eecb5ee9b2e4436e6ae069989a83239d4f54d7cee393e320c",
  guestLock: "87ae1246c7cf2691ab135e0ad8ee79167e23d80aad386b531f7381e9d80f9f48",
  entrypoint: "dd0384751156b5e61d59c166ff09a80b3abdfcab576080b9f7be3603ac520f2d",
  driver: "cf650fd0b4890751f65ea43260c15cf68c5ce8a99ea9faf4723a62050d7252b1",
  codeKeccak: "0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd",
  verifierHash: "0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696",
  vkRoot: "0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352",
  verifier: "0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2",
  acvpElf: "165883fa8681507d92f97eb879030c41f10d2592c3dce229fa951f8ec91fc8e0",
  acvpVkey: "0x00516cd6333c30f52557608680aa5e10e228856610ce7cba616640af56a93bd7",
};

describe("SP1 implementation lane — the generated PROGRAM_VKEY designation", function () {
  let designations: ProgramDesignation[];
  let d1: ProgramDesignation;

  before(function () {
    designations = readDesignations(".");
    d1 = designations[0];
  });

  it("the committed first designation is the derivation from SP1-TD1's evidence, byte for byte", function () {
    const derived = deriveInitialDesignation(readDecisionContext("."));
    expect(serializeDesignation(derived)).to.equal(
      readFileSync(resolve("evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json"), "utf8"),
    );
    expect(initialDesignationDriftErrors(designations, readDecisionContext("."))).to.deep.equal([]);
    expect(validateDesignationsInRepo(".")).to.deep.equal([]);
  });

  it("binds subject → digest-pinned procedure → lockfile → ELF → vkey → verifier, as SP1-TD1 measured them", function () {
    expect(d1.schema).to.equal(DESIGNATION_SCHEMA);
    expect([d1.id, d1.sequence, d1.program, d1.predecessor, d1.succession]).to.deep.equal([
      "mldsa65-withdrawal-d1",
      1,
      "mldsa65-withdrawal",
      null,
      null,
    ]);
    expect(d1.subject).to.deep.equal({
      zkvmGuestTree: TD1.guestTree,
      zkvmHostTree: TD1.hostTree,
      sourceManifestSha256: TD1.manifest,
      guestCargoLockSha256: TD1.guestLock,
    });
    expect(d1.procedure).to.include({
      id: "vendor-image-host-flow",
      image: TD1.image,
      platform: "linux/amd64",
      linuxAmd64Manifest: TD1.amd64Manifest,
      config: TD1.config,
      target: "riscv64im-succinct-zkvm-elf",
      guestLock: "UNCHANGED_BY_THE_BUILD",
    });
    expect(d1.procedure.image).to.match(/@sha256:[0-9a-f]{64}$/);
    expect(d1.procedure.entrypoint).to.deep.equal({
      path: "evidence/zk/sp1-td1/canonical-procedure/host-build-in-container.sh",
      sha256: TD1.entrypoint,
    });
    expect(d1.procedure.driver).to.deep.equal({
      path: "evidence/zk/sp1-td1/canonical-procedure/observe.sh",
      sha256: TD1.driver,
    });
    expect(d1.procedure.sp1).to.deep.equal({
      "sp1-zkvm": "=6.3.1",
      "sp1-sdk": "=6.3.1",
      "sp1-build": "=6.3.1",
      circuitVersion: "v6.1.0",
    });
    expect(d1.elf).to.deep.equal({ sha256: TD1.elf, bytes: TD1.elfBytes });
    expect(d1.programVKey).to.equal(TD1.vkey);
    expect(d1.hosts).to.deep.equal(["developer-workstation", "github-hosted-runner"]);
    expect(d1.vkeyRecomputed.conflicting).to.equal(0);
    expect(d1.vkeyRecomputed.agreeing).to.be.greaterThan(0);
    expect(d1.vkeyRecomputed.tool).to.match(/cargo-prove/);
    expect(d1.verifier).to.include({
      version: "v6.1.0",
      address: TD1.verifier,
      runtimeCodeKeccak: TD1.codeKeccak,
      verifierHash: TD1.verifierHash,
      vkRoot: TD1.vkRoot,
    });
    expect(d1.verifier.measuredChains.map((c) => c.chainId)).to.deep.equal(["1", "8453", "11155111", "84532"]);
    expect(d1.verifier.measuredChains.every((c) => c.codeKeccak === TD1.codeKeccak)).to.equal(true);
    expect(d1.doNotPin).to.deep.equal([{ program: "mldsa65-acvp", elfSha256: TD1.acvpElf, vkey: TD1.acvpVkey }]);
    expect(d1.soundness).to.equal(SOUNDNESS_NOT_ESTABLISHED);
  });

  it("its identity is the one the consumers store on chain: keccak256(abi.encode(code hash, PROGRAM_VKEY))", async function () {
    expect(d1.identity).to.equal(ethers.keccak256(ABI.encode(["bytes32", "bytes32"], [TD1.codeKeccak, TD1.vkey])));
    const zk = await (
      await ethers.getContractFactory("ZKMLDSAVerifier")
    ).deploy(await deployPinnedSp1Verifier(), d1.programVKey, TEST_HALT_PRINCIPAL);
    const vault = await (await ethers.getContractFactory("WalletWallVault")).deploy(await zk.getAddress());
    expect(await vault.pqVerifierIdentity()).to.equal(d1.identity);
  });

  it("the compiled wrapper's pins are this designation's verifier (no verifier drift)", function () {
    const builds = readWrapperBuilds(".");
    const latest = builds[builds.length - 1];
    expect(compatibleDesignations(latest, designations).map((d) => d.id)).to.deep.equal(["mldsa65-withdrawal-d1"]);
    const otherCode = clone(latest);
    otherCode.pins.sp1VerifierCodehash = ethers.id("another verifier");
    expect(compatibleDesignations(otherCode, designations)).to.deep.equal([]);
    for (const field of ["sp1VerifierHash", "vkRoot", "version"] as const) {
      const other = clone(latest);
      other.pins[field] = field === "version" ? "v6.1.1" : ethers.ZeroHash;
      expect(compatibleDesignations(other, designations), field).to.deep.equal([]);
    }
  });

  describe("only evidence moves it", function () {
    it("a hand-edited value in the committed designation is drift, whatever the field", function () {
      const edits: [string, (d: ProgramDesignation) => void][] = [
        ["vkey", (d) => (d.programVKey = "0x" + "11".repeat(32))],
        ["ELF", (d) => (d.elf.sha256 = "22".repeat(32))],
        ["image", (d) => (d.procedure.image = "ghcr.io/succinctlabs/sp1:v6.3.1")],
        ["lockfile", (d) => (d.subject.guestCargoLockSha256 = "33".repeat(32))],
        ["verifier", (d) => (d.verifier.runtimeCodeKeccak = ethers.ZeroHash)],
        ["entrypoint", (d) => (d.procedure.entrypoint.sha256 = "44".repeat(32))],
      ];
      for (const [label, edit] of edits) {
        const set = clone(designations);
        edit(set[0]);
        expect(initialDesignationDriftErrors(set, readDecisionContext(".")).join("\n"), label).to.match(
          /not what SP1-TD1's evidence derives/,
        );
      }
    });

    it("changed evidence changes the derivation or refuses it: no designation without the evidence contract", function () {
      const ctx = readDecisionContext(".");
      const refused: [string, (c: any) => void, RegExp][] = [
        // The vendor image index must hash to its pinned digest.
        ["image digest", (c) => (c.image.pinnedIndex.bodySha256 = "sha256:" + "0".repeat(64)), /does not designate/],
        // One ELF with two vkeys (a cross-check disagrees) is a contradiction.
        [
          "conflicting outside recompute",
          (c) =>
            c.sp1p1Identity.crossChecks.vkeyFromElf.results.push({
              source: "C-host",
              program: "mldsa65-withdrawal",
              elfSha256: TD1.elf,
              vkey: "0x" + "55".repeat(32),
            }),
          /does not designate/,
        ],
        // A chain whose verifier code differs breaks the trust target's code identity.
        [
          "chain code",
          (c) => (c.chain.chains["8453"].verifiers["v6.1.0"].codeKeccak = ethers.ZeroHash),
          /does not designate/,
        ],
        // The second host disappearing leaves one host: not reproduced on independent hosts.
        [
          "one host",
          (c) =>
            (c.sp1p1Identity.environments = c.sp1p1Identity.environments.filter(
              (e: any) => e.hostId !== "github-hosted-runner",
            )),
          /does not designate/,
        ],
      ];
      for (const [label, change, rule] of refused) {
        const changed = clone(ctx);
        change(changed);
        expect(() => deriveInitialDesignation(changed), label).to.throw(rule);
      }
      // A working-tree change does not move a designation: it is derived as of the subject its evidence measured.
      const moved = clone(ctx);
      moved.workingTreeManifest = moved.workingTreeManifest.map((e: any) =>
        e.path === "zkvm/guest/src/bin/withdrawal.rs" ? { ...e, sha256: "66".repeat(32) } : e,
      );
      moved.gitTrees = { guest: "77".repeat(20), host: moved.gitTrees.host };
      expect(serializeDesignation(deriveInitialDesignation(moved))).to.equal(serializeDesignation(d1));
    });

    it("the zkvm subject on disk and at HEAD must be the latest designation's (the stale-vkey tripwire)", function () {
      expect(subjectFreshnessErrors(d1, ".")).to.deep.equal([]);
      const cases: [string, (d: ProgramDesignation) => void, RegExp][] = [
        ["guest tree", (d) => (d.subject.zkvmGuestTree = "88".repeat(20)), /HEAD:zkvm\/guest/],
        ["host tree", (d) => (d.subject.zkvmHostTree = "99".repeat(20)), /HEAD:zkvm\/host/],
        ["manifest", (d) => (d.subject.sourceManifestSha256 = "aa".repeat(32)), /zkvm guest\/host sources on disk/],
        ["lockfile", (d) => (d.subject.guestCargoLockSha256 = "bb".repeat(32)), /zkvm\/guest\/Cargo.lock/],
      ];
      for (const [label, change, rule] of cases) {
        const d = clone(d1);
        change(d);
        expect(subjectFreshnessErrors(d, ".").join("\n"), label).to.match(rule);
        expect(subjectFreshnessErrors(d, ".").join("\n"), label).to.match(/needs a new designation/);
      }
    });

    it("a designation never claims soundness, and the set is well formed", function () {
      expect(designationSetErrors(designations)).to.deep.equal([]);
      const cases: [string, (s: ProgramDesignation[]) => void, RegExp][] = [
        ["soundness", (s) => ((s[0] as any).soundness = "ESTABLISHED"), /soundness/],
        ["schema", (s) => (s[0].schema = "walletwall.other.v1"), /schema/],
        ["id", (s) => (s[0].id = "mldsa65-withdrawal-d9"), /id/],
        ["identity", (s) => (s[0].identity = ethers.ZeroHash), /identity/],
        ["mutable image tag", (s) => (s[0].procedure.image = "ghcr.io/succinctlabs/sp1:v6.3.1"), /digest/],
        ["first has a predecessor", (s) => (s[0].predecessor = { id: "x", identity: ethers.ZeroHash }), /predecessor/],
      ];
      for (const [label, change, rule] of cases) {
        const set = clone(designations);
        change(set);
        expect(designationSetErrors(set).join("\n"), label).to.match(rule);
      }
    });
  });
});
