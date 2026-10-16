/**
 * SP1 implementation lane: wrapper build records (closes SP1-TD2 review residual R2-3;
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD2 judged every registered wrapper against TODAY's compiled ZKMLDSAVerifier, so any later change to the
 * wrapper's compiled code (a solc bump, this lane's pin) would turn every older registry entry "not genuine". Each
 * build of the wrapper is now recorded once, from the compiler's own output, in evidence/zk/sp1/wrapper-builds/, and
 * a deployed wrapper is judged against the build it was deployed from. CI refuses a compiled wrapper that is not the
 * latest recorded build, so every deployable wrapper has a record to point at.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import { deployPinnedSp1Verifier } from "./helpers/sp1PinnedVerifier";
import { TEST_HALT_PRINCIPAL } from "./helpers/zkVerifierHelpers";
import { skipWhenInstrumented } from "./helpers/instrumented";
import {
  WRAPPER_BUILDS_DIR,
  WRAPPER_BUILD_SCHEMA,
  buildFromCompilation,
  buildMatching,
  compareCurrentBuild,
  currentBuildErrors,
  matchesBuild,
  nextBuildRecord,
  readWrapperBuilds,
  wrapperBuildErrors,
  type WrapperBuild,
} from "../scripts/lib/sp1-wrapper-build";

const RECEIPT = JSON.parse(readFileSync(resolve("evidence/zk/sp1-td1/decision-receipt.json"), "utf8"));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const flipByte = (hex: string, at: number) => {
  const b = ethers.getBytes(hex);
  b[at] ^= 0x01;
  return ethers.hexlify(b);
};

describe("SP1 implementation lane — wrapper build records", function () {
  let builds: WrapperBuild[];
  let latest: WrapperBuild;

  before(function () {
    builds = readWrapperBuilds(".");
    latest = builds[builds.length - 1];
  });

  it("the compiled ZKMLDSAVerifier is the latest recorded build, and the records are well formed", function () {
    skipWhenInstrumented(this);
    expect(currentBuildErrors(".")).to.deep.equal([]);
    expect(wrapperBuildErrors(builds)).to.deep.equal([]);
    expect(builds.length).to.be.greaterThan(0);
    expect(latest.schema).to.equal(WRAPPER_BUILD_SCHEMA);
    expect(latest.contract).to.deep.equal({
      source: "contracts/verifiers/ZKMLDSAVerifier.sol",
      name: "ZKMLDSAVerifier",
    });
    expect(latest.compiler).to.deep.equal({
      solc: "0.8.24+commit.e11b9ed9",
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
    });
    // The compilation unit: the wrapper and the two interfaces it imports, each hashed as committed.
    expect(latest.sources.map((s) => s.path)).to.deep.equal([
      "contracts/IPQCVerifier.sol",
      "contracts/verifiers/IHaltableVerifier.sol",
      "contracts/verifiers/ZKMLDSAVerifier.sol",
    ]);
    for (const s of latest.sources) {
      expect(s.sha256, s.path).to.equal(ethers.sha256(readFileSync(resolve(s.path))).slice(2));
    }
  });

  it("records the pins the compiled contract enforces, and they are SP1-TD1's trust target", async function () {
    const zk = await (
      await ethers.getContractFactory("ZKMLDSAVerifier")
    ).deploy(await deployPinnedSp1Verifier(), RECEIPT.decisions.PROGRAM_VKEY_DESIGNATION.vkey, TEST_HALT_PRINCIPAL);
    expect(latest.pins).to.deep.equal({
      sp1VerifierCodehash: await zk.SP1_VERIFIER_CODEHASH(),
      sp1VerifierHash: await zk.SP1_VERIFIER_HASH(),
      vkRoot: await zk.SP1_VK_ROOT(),
      version: await zk.SP1_VERSION(),
    });
    expect(latest.pins).to.deep.equal({
      sp1VerifierCodehash: RECEIPT.trustTarget.codeKeccak,
      sp1VerifierHash: RECEIPT.trustTarget.verifierHash,
      vkRoot: RECEIPT.trustTarget.vkRoot,
      version: RECEIPT.trustTarget.version,
    });
  });

  describe("judging a deployed runtime against a build", function () {
    let runtime: string;

    before(async function () {
      skipWhenInstrumented(this);
      const zk = await (
        await ethers.getContractFactory("ZKMLDSAVerifier")
      ).deploy(await deployPinnedSp1Verifier(), RECEIPT.decisions.PROGRAM_VKEY_DESIGNATION.vkey, TEST_HALT_PRINCIPAL);
      runtime = await ethers.provider.getCode(await zk.getAddress());
    });

    it("a deployed wrapper matches its build: immutables differ per deployment, everything else is the template", function () {
      expect(runtime).to.not.equal(latest.runtime.template);
      expect(matchesBuild(runtime, latest)).to.equal(true);
      expect(buildMatching(runtime, builds)?.id).to.equal(latest.id);
    });

    it("any changed code byte or length is another build; the metadata trailer is not compared (SP1-TD2's rule)", function () {
      const firstImmutable = Math.min(
        ...Object.values(latest.runtime.immutableReferences)
          .flat()
          .map((r) => r.start),
      );
      expect(matchesBuild(flipByte(runtime, firstImmutable - 1), latest), "code before an immutable").to.equal(false);
      expect(
        matchesBuild(flipByte(runtime, latest.runtime.metadataRegionStart - 1), latest),
        "last code byte",
      ).to.equal(false);
      // The trailer hashes the compilation job (the sources and remappings Hardhat grouped with the wrapper), so a
      // fresh compile of the same source can carry another one: inside the IPFS hash it is the same build.
      expect(matchesBuild(flipByte(runtime, latest.runtime.metadataRegionStart + 12), latest), "metadata").to.equal(
        true,
      );
      expect(matchesBuild(runtime + "00", latest), "one byte longer").to.equal(false);
      expect(matchesBuild(runtime.slice(0, -2), latest), "one byte shorter").to.equal(false);
      expect(matchesBuild("0x", latest), "no code").to.equal(false);
      expect(buildMatching(flipByte(runtime, 0), builds)).to.equal(null);
      // Inside an immutable slot any value is the same build (the slot is the deployment's, not the build's).
      expect(matchesBuild(flipByte(runtime, firstImmutable), latest)).to.equal(true);
    });

    it("an old build stays the build of the wrappers deployed from it after the contract changes", function () {
      // A later build (here: the same record with another template) never makes an older deployment "not genuine".
      const later = clone(latest);
      later.id = "zkmldsa-verifier-b999";
      later.sequence = latest.sequence + 1;
      later.runtime.template = flipByte(latest.runtime.template, 10);
      later.runtime.templateKeccak = ethers.keccak256(later.runtime.template);
      expect(buildMatching(runtime, [...builds, later])?.id).to.equal(latest.id);
    });
  });

  describe("a record that departs from the compiler is refused", function () {
    it("the current compilation must equal the latest record, field by field", function () {
      skipWhenInstrumented(this);
      const current = buildFromCompilation(".");
      expect(compareCurrentBuild(current, builds)).to.deep.equal([]);
      const cases: [string, (b: WrapperBuild) => void, RegExp][] = [
        ["a template byte", (b) => (b.runtime.template = flipByte(b.runtime.template, 5)), /runtime/],
        ["a pin", (b) => (b.pins.vkRoot = ethers.ZeroHash), /pins/],
        ["the compiler", (b) => (b.compiler.optimizer.runs = 201), /compiler/],
        ["an immutable position", (b) => (Object.values(b.runtime.immutableReferences)[0][0].start += 1), /runtime/],
        ["the metadata boundary", (b) => (b.runtime.metadataRegionStart -= 1), /runtime/],
      ];
      for (const [label, tamper, rule] of cases) {
        const changed = clone(current);
        tamper(changed);
        expect(compareCurrentBuild(changed, builds).join("\n"), label).to.match(rule);
        expect(compareCurrentBuild(changed, builds).join("\n"), label).to.match(/npm run sp1:wrapper-build/);
      }
      // The same code from another compilation job (another metadata trailer), or from sources that differ only where
      // the code does not (a comment), is the same build: the record keeps the sources it was built from as provenance.
      const otherJob = clone(current);
      otherJob.runtime.template = flipByte(current.runtime.template, current.runtime.metadataRegionStart + 12);
      otherJob.runtime.templateKeccak = ethers.keccak256(otherJob.runtime.template);
      expect(compareCurrentBuild(otherJob, builds), "another trailer").to.deep.equal([]);
      const commented = clone(current);
      commented.sources[0].sha256 = "0".repeat(64);
      expect(compareCurrentBuild(commented, builds), "a source that changes no code").to.deep.equal([]);
      expect(compareCurrentBuild(current, []).join("\n")).to.match(/no wrapper build is recorded/);
    });

    it("the record set is well formed: schema, ids, contiguous sequences, self-consistent hashes", function () {
      const cases: [string, (bs: WrapperBuild[]) => void, RegExp][] = [
        ["schema", (bs) => (bs[0].schema = "walletwall.other.v1"), /schema/],
        ["id", (bs) => (bs[0].id = "zkmldsa-verifier-b7"), /id/],
        ["sequence", (bs) => (bs[0].sequence = 2), /sequence/],
        ["template hash", (bs) => (bs[0].runtime.templateKeccak = ethers.ZeroHash), /templateKeccak/],
        ["byte count", (bs) => (bs[0].runtime.bytes += 1), /bytes/],
        ["pin shape", (bs) => (bs[0].pins.sp1VerifierCodehash = "0x1234"), /pins/],
        ["duplicate", (bs) => bs.push(clone(bs[0])), /twice|sequence/],
        [
          "the same code recorded again under another trailer",
          (bs) => {
            const again = clone(bs[0]);
            again.id = "zkmldsa-verifier-b2";
            again.sequence = 2;
            again.runtime.template = flipByte(again.runtime.template, again.runtime.metadataRegionStart + 12);
            again.runtime.templateKeccak = ethers.keccak256(again.runtime.template);
            bs.push(again);
          },
          /the same code is recorded twice/,
        ],
      ];
      for (const [label, tamper, rule] of cases) {
        const changed = clone(builds);
        tamper(changed);
        expect(wrapperBuildErrors(changed).join("\n"), label).to.match(rule);
      }
    });

    it("a new build is appended as the next record; an unchanged one appends nothing", function () {
      skipWhenInstrumented(this);
      const current = buildFromCompilation(".");
      expect(nextBuildRecord(current, builds)).to.equal(null);
      const changed = clone(current);
      changed.runtime.template = flipByte(changed.runtime.template, 7);
      changed.runtime.templateKeccak = ethers.keccak256(changed.runtime.template);
      const next = nextBuildRecord(changed, builds)!;
      expect(next.sequence).to.equal(latest.sequence + 1);
      expect(next.id).to.equal(`zkmldsa-verifier-b${latest.sequence + 1}`);
      expect(wrapperBuildErrors([...builds, next])).to.deep.equal([]);
      const trailerOnly = clone(current);
      trailerOnly.runtime.template = flipByte(current.runtime.template, current.runtime.metadataRegionStart + 12);
      trailerOnly.runtime.templateKeccak = ethers.keccak256(trailerOnly.runtime.template);
      expect(nextBuildRecord(trailerOnly, builds), "another trailer appends nothing").to.equal(null);
      expect(WRAPPER_BUILDS_DIR).to.equal("evidence/zk/sp1/wrapper-builds");
    });
  });
});
