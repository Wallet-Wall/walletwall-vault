/**
 * SP1 implementation lane: successor designations (docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD2's recovery refuses the halted identity on chain, and its binding gate admits a recovery wrapper off a local
 * chain only through a successor designation. A successor is derived from an evidence bundle that meets the same
 * evidence contract as the first designation — the subject, the canonical digest-pinned procedure, two hosts agreeing
 * on the ELF and vkey with the guest lockfile unchanged, an outside vkey recompute with no conflict, the SP1 verifier —
 * names its predecessor and why it succeeds it, and must carry an identity no earlier designation has. Earlier files
 * are never touched. A designation says which program and verifier these are; it never says they are sound.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import {
  DESIGNATION_EVIDENCE_SCHEMA,
  SOUNDNESS_NOT_ESTABLISHED,
  deriveSuccessorDesignation,
  successorDriftErrors,
  designationSetErrors,
  identityOf,
  readDesignations,
  serializeDesignation,
  type DesignationEvidenceBundle,
  type ProgramDesignation,
} from "../scripts/lib/sp1-designation";
import { sourceManifestDigest, workingTreeSourceManifest } from "../scripts/lib/sp1-p1-stop-receipt";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const word = (byte: string) => "0x" + byte.repeat(32);
const hex64 = (byte: string) => byte.repeat(32);
const REASON =
  "the designated identity was halted for a defect in the withdrawal guest; this build fixes the guest and is independently established";

/** A successor build of the withdrawal program: new guest sources, so a new ELF and vkey, on the same verifier. */
function newProgramBundle(d1: ProgramDesignation): DesignationEvidenceBundle {
  const lock = hex64("4c");
  const manifest = [
    { path: "zkvm/guest/Cargo.lock", sha256: lock },
    { path: "zkvm/guest/Cargo.toml", sha256: hex64("01") },
    { path: "zkvm/guest/src/bin/withdrawal.rs", sha256: hex64("02") },
    { path: "zkvm/host/Cargo.toml", sha256: hex64("03") },
  ];
  const programs = {
    "mldsa65-withdrawal": { elfSha256: hex64("e1"), elfBytes: 206_800, vkey: word("0a") },
    "mldsa65-acvp": { elfSha256: hex64("e2"), elfBytes: 195_900, vkey: word("0b") },
  };
  const build = (hostId: string) => ({
    hostId,
    image: d1.procedure.image,
    guestLockBefore: lock,
    guestLockAfter: lock,
    programs: clone(programs),
  });
  return {
    schema: DESIGNATION_EVIDENCE_SCHEMA,
    program: "mldsa65-withdrawal",
    subject: { zkvmGuestTree: "a1".repeat(20), zkvmHostTree: d1.subject.zkvmHostTree, sourceManifest: manifest },
    procedure: clone(d1.procedure),
    builds: [build("github-hosted-runner-a"), build("github-hosted-runner-b")],
    vkeyRecompute: {
      tool: "cargo-prove sp1 (8252c29)",
      toolSha256: hex64("c0"),
      ranOn: "github-hosted-runner-c",
      results: [{ program: "mldsa65-withdrawal", elfSha256: hex64("e1"), vkey: word("0a") }],
    },
    verifier: { sameAs: d1.id },
    succession: { predecessor: d1.id, reason: REASON },
  };
}

describe("SP1 implementation lane — successor designations", function () {
  let set: ProgramDesignation[];
  let d1: ProgramDesignation;

  before(function () {
    set = readDesignations(".");
    d1 = set[0];
  });

  it("a genuinely new identity is designated next, naming its predecessor and why, and earlier files are untouched", function () {
    const before = set.map(serializeDesignation);
    const d2 = deriveSuccessorDesignation(newProgramBundle(d1), set);
    expect([d2.id, d2.sequence, d2.program]).to.deep.equal(["mldsa65-withdrawal-d2", 2, "mldsa65-withdrawal"]);
    expect(d2.predecessor).to.deep.equal({ id: d1.id, identity: d1.identity });
    expect(d2.succession).to.deep.equal({ reason: REASON });
    expect(d2.programVKey).to.equal(word("0a"));
    expect(d2.elf).to.deep.equal({ sha256: hex64("e1"), bytes: 206_800 });
    expect(d2.verifier).to.deep.equal(d1.verifier);
    expect(d2.identity).to.equal(identityOf(d1.verifier.runtimeCodeKeccak, word("0a")));
    expect(d2.identity).to.not.equal(d1.identity);
    expect(d2.hosts).to.deep.equal(["github-hosted-runner-a", "github-hosted-runner-b"]);
    expect(d2.subject.guestCargoLockSha256).to.equal(hex64("4c"));
    expect(d2.soundness).to.equal(SOUNDNESS_NOT_ESTABLISHED);
    expect(designationSetErrors([...set, d2])).to.deep.equal([]);
    expect(set.map(serializeDesignation)).to.deep.equal(before);
  });

  describe("no successor can alias an earlier identity", function () {
    it("the same verifier code and the same PROGRAM_VKEY are refused: a redeployment of the halted identity", function () {
      const bundle = newProgramBundle(d1);
      for (const b of bundle.builds)
        b.programs["mldsa65-withdrawal"] = { elfSha256: d1.elf.sha256, elfBytes: d1.elf.bytes, vkey: d1.programVKey };
      bundle.vkeyRecompute.results = [
        { program: "mldsa65-withdrawal", elfSha256: d1.elf.sha256, vkey: d1.programVKey },
      ];
      expect(() => deriveSuccessorDesignation(bundle, set)).to.throw(
        /identity .* is already designated by mldsa65-withdrawal-d1/,
      );
    });

    it("changing only the verifier's address is the same identity, refused", function () {
      const bundle = newProgramBundle(d1);
      for (const b of bundle.builds)
        b.programs["mldsa65-withdrawal"] = { elfSha256: d1.elf.sha256, elfBytes: d1.elf.bytes, vkey: d1.programVKey };
      bundle.vkeyRecompute.results = [
        { program: "mldsa65-withdrawal", elfSha256: d1.elf.sha256, vkey: d1.programVKey },
      ];
      bundle.verifier = { ...clone(d1.verifier), address: "0x000000000000000000000000000000000000dEaD" } as any;
      expect(() => deriveSuccessorDesignation(bundle, set)).to.throw(
        /identity .* is already designated by mldsa65-withdrawal-d1/,
      );
    });

    it("a set where a later designation repeats an earlier identity is refused, whatever its id says", function () {
      const d2 = deriveSuccessorDesignation(newProgramBundle(d1), set);
      const alias = clone(d2);
      alias.programVKey = d1.programVKey;
      alias.identity = d1.identity;
      expect(designationSetErrors([...set, alias]).join("\n")).to.match(/already designated by mldsa65-withdrawal-d1/);
    });

    it("one ELF never maps to two vkeys across the set, however its SP1 pins are spelled", function () {
      const d2 = deriveSuccessorDesignation(newProgramBundle(d1), set);
      const twoVkeys = (sp1: Record<string, string>) => {
        const d = clone(d2);
        d.elf = clone(d1.elf);
        d.procedure.sp1 = sp1;
        return designationSetErrors([...set, d]).join("\n");
      };
      const reversed = Object.fromEntries(Object.entries(d1.procedure.sp1).reverse());
      const padded = Object.fromEntries(Object.entries(d1.procedure.sp1).map(([k, v]) => [k, `${v} `]));
      expect(JSON.stringify(reversed)).to.not.equal(JSON.stringify(d1.procedure.sp1));
      for (const [label, sp1] of [
        ["the same pins", d1.procedure.sp1],
        ["reordered keys", reversed],
        ["padded values", padded],
      ] as const) {
        expect(twoVkeys(sp1), label).to.match(/one ELF maps to two vkeys/);
      }
      // Another SP1 release is another prover: the same ELF may then have another vkey.
      const other = Object.fromEntries(Object.entries(d1.procedure.sp1).map(([k, v]) => [k, `${v}-other`]));
      expect(twoVkeys(other)).to.not.match(/one ELF maps to two vkeys/);
    });

    it("two designations of one subject under one procedure are refused: one build, two designations", function () {
      const d2 = deriveSuccessorDesignation(newProgramBundle(d1), set);
      const twin = clone(d2);
      twin.subject = clone(d1.subject);
      expect(designationSetErrors([...set, twin]).join("\n")).to.match(/share a subject under one procedure/);
      expect(designationSetErrors([...set, d2])).to.deep.equal([]);
    });
  });

  describe("a successor meets the first designation's evidence contract", function () {
    const refused: [string, (b: DesignationEvidenceBundle) => void, RegExp][] = [
      ["one host", (b) => b.builds.pop(), /two hosts/],
      ["the same host twice", (b) => (b.builds[1].hostId = b.builds[0].hostId), /two hosts/],
      [
        "hosts disagree on the ELF",
        (b) => (b.builds[1].programs["mldsa65-withdrawal"].elfSha256 = hex64("e9")),
        /agree/,
      ],
      ["hosts disagree on the vkey", (b) => (b.builds[1].programs["mldsa65-withdrawal"].vkey = word("09")), /agree/],
      ["no outside recompute", (b) => (b.vkeyRecompute.results = []), /recomputed outside the build/],
      [
        "one ELF, two vkeys",
        (b) =>
          b.vkeyRecompute.results.push({ program: "mldsa65-withdrawal", elfSha256: hex64("e1"), vkey: word("0c") }),
        /PROGRAM_IDENTITY_CONTRADICTION/,
      ],
      ["a mutable image tag", (b) => (b.procedure.image = "ghcr.io/succinctlabs/sp1:v6.3.1"), /its own decision/],
      [
        "a build on another image",
        (b) => (b.builds[0].image = "ghcr.io/succinctlabs/sp1@sha256:" + hex64("ee")),
        /procedure's image/,
      ],
      ["the lockfile changed in the build", (b) => (b.builds[0].guestLockAfter = hex64("4d")), /lockfile/],
      ["the lockfile is not the subject's", (b) => (b.builds[1].guestLockBefore = hex64("4e")), /lockfile/],
      ["another procedure", (b) => (b.procedure.id = "repository-local"), /its own decision/],
      // Every field of the procedure is the first designation's: another one is another decision, not a successor.
      [
        "another image by digest",
        (b) => (b.procedure.image = "ghcr.io/someone-else/not-sp1@sha256:" + hex64("ab")),
        /its own decision/,
      ],
      ["another platform", (b) => (b.procedure.platform = "linux/arm64"), /its own decision/],
      ["another image manifest", (b) => (b.procedure.linuxAmd64Manifest = "sha256:" + hex64("ac")), /its own decision/],
      ["another image config", (b) => (b.procedure.config = "sha256:" + hex64("ad")), /its own decision/],
      ["another entrypoint", (b) => (b.procedure.entrypoint.sha256 = hex64("00")), /its own decision/],
      ["another driver", (b) => (b.procedure.driver.sha256 = hex64("00")), /its own decision/],
      ["other SP1 pins", (b) => (b.procedure.sp1 = { "sp1-zkvm": "=0.0.1" }), /its own decision/],
      ["another target", (b) => (b.procedure.target = "x86_64-unknown-linux-gnu"), /its own decision/],
      ["another guest lock policy", (b) => (b.procedure.guestLock = "RESOLVED_BY_THE_BUILD"), /its own decision/],
      ["a recompute that names no tool digest", (b) => (b.vkeyRecompute.toolSha256 = "not-a-hash"), /tool's sha256/],
      ["another program", (b) => (b.program = "mldsa65-acvp"), /program/],
      ["a soundness claim", (b) => ((b as any).soundness = "ESTABLISHED"), /soundness/],
      ["an unknown verifier reference", (b) => (b.verifier = { sameAs: "mldsa65-withdrawal-d7" }), /verifier/],
      [
        "a new SP1 verifier (no tooling derives its trust target yet)",
        (b) => (b.verifier = { ...clone(d1.verifier), runtimeCodeKeccak: word("77") } as never),
        /cannot be designated by this tooling/,
      ],
    ];
    for (const [label, change, rule] of refused) {
      it(`refuses ${label}`, function () {
        const bundle = newProgramBundle(d1);
        change(bundle);
        expect(() => deriveSuccessorDesignation(bundle, set)).to.throw(rule);
      });
    }

    it("refuses the subject of an earlier designation: under the same procedure it is that designation's build", function () {
      // The current tree is d1's subject: a bundle claiming another ELF or vkey for it contradicts d1's measured build,
      // and one claiming d1's own is d1's identity. Either way it is no successor.
      const same = newProgramBundle(d1);
      same.subject = {
        zkvmGuestTree: d1.subject.zkvmGuestTree,
        zkvmHostTree: d1.subject.zkvmHostTree,
        sourceManifest: workingTreeSourceManifest("."),
      };
      expect(sourceManifestDigest(same.subject.sourceManifest)).to.equal(d1.subject.sourceManifestSha256);
      expect(() => deriveSuccessorDesignation(same, set)).to.throw(/the subject is mldsa65-withdrawal-d1's/);
      const trees = newProgramBundle(d1);
      trees.subject.zkvmGuestTree = d1.subject.zkvmGuestTree;
      trees.subject.zkvmHostTree = d1.subject.zkvmHostTree;
      expect(() => deriveSuccessorDesignation(trees, set)).to.throw(/the subject is mldsa65-withdrawal-d1's/);
      // A new guest alone is a new subject (the positive case above).
      expect(() => deriveSuccessorDesignation(newProgramBundle(d1), set)).to.not.throw();
    });

    it("records what the recompute measured: agreeing results, conflicts, distinct computations", function () {
      const bundle = newProgramBundle(d1);
      bundle.vkeyRecompute.results.push({ program: "mldsa65-withdrawal", elfSha256: hex64("e1"), vkey: word("0a") });
      expect(deriveSuccessorDesignation(bundle, set).vkeyRecomputed).to.deep.equal({
        tool: "cargo-prove sp1 (8252c29)",
        agreeing: 2,
        conflicting: 0,
        distinctComputations: 1,
      });
    });

    it("refuses an unknown predecessor and a missing reason", function () {
      expect(() =>
        deriveSuccessorDesignation(
          { ...newProgramBundle(d1), succession: { predecessor: "mldsa65-withdrawal-d9", reason: REASON } },
          set,
        ),
      ).to.throw(/predecessor/);
      expect(() =>
        deriveSuccessorDesignation({ ...newProgramBundle(d1), succession: { predecessor: d1.id, reason: "  " } }, set),
      ).to.throw(/reason/);
    });

    it("a successor whose recorded predecessor or reason was edited is refused by the set rules", function () {
      const d2 = deriveSuccessorDesignation(newProgramBundle(d1), set);
      const cases: [string, (d: ProgramDesignation) => void, RegExp][] = [
        ["predecessor identity", (d) => (d.predecessor = { id: d1.id, identity: word("12") }), /predecessor/],
        ["no predecessor", (d) => (d.predecessor = null), /predecessor/],
        ["no reason", (d) => (d.succession = { reason: "" }), /reason/],
      ];
      for (const [label, change, rule] of cases) {
        const changed = clone(d2);
        change(changed);
        expect(designationSetErrors([...set, changed]).join("\n"), label).to.match(rule);
      }
    });
  });
  describe("a committed successor is re-derived from its own bundle", function () {
    it("passes when designation and bundle are as derived; an edit to either, or a missing bundle, is refused", function () {
      const bundle = newProgramBundle(d1);
      const d2 = deriveSuccessorDesignation(bundle, set);
      expect(successorDriftErrors([...set, d2], { [d2.id]: bundle })).to.deep.equal([]);
      expect(successorDriftErrors([...set, d2], {}).join("\n")).to.match(/evidence bundle .* is missing/);
      const editedBundle = clone(bundle);
      editedBundle.builds[0].hostId = "someone-else";
      expect(successorDriftErrors([...set, d2], { [d2.id]: editedBundle }).join("\n")).to.match(
        /not the one it was derived from/,
      );
      const editedDesignation = clone(d2);
      editedDesignation.hosts = ["github-hosted-runner-a", "github-hosted-runner-z"];
      expect(successorDriftErrors([...set, editedDesignation], { [d2.id]: bundle }).join("\n")).to.match(
        /not what its evidence bundle derives/,
      );
      const otherReason = clone(d2);
      otherReason.succession = { reason: "a different story" };
      expect(successorDriftErrors([...set, otherReason], { [d2.id]: bundle }).join("\n")).to.match(
        /not what its evidence bundle derives/,
      );
      // The reason lives in the bundle too: editing it there is a new bundle, which the digest refuses.
      const otherBundleReason = clone(bundle);
      otherBundleReason.succession.reason = "a different story";
      expect(successorDriftErrors([...set, d2], { [d2.id]: otherBundleReason }).join("\n")).to.match(
        /not the one it was derived from/,
      );
    });
  });
  describe("the designation CLI", function () {
    it("appends a successor and its bundle from a bundle file, and never overwrites either", function () {
      const dir = mkdtempSync(join(tmpdir(), "sp1-successor-"));
      try {
        mkdirSync(join(dir, "evidence/zk/sp1/designations"), { recursive: true });
        writeFileSync(join(dir, "evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json"), serializeDesignation(d1));
        const bundle = newProgramBundle(d1);
        writeFileSync(join(dir, "bundle.json"), JSON.stringify(bundle, null, 2));
        const run = () =>
          spawnSync(
            process.execPath,
            [
              "--import",
              import.meta.resolve("tsx"),
              resolve("scripts/generate-sp1-designation.ts"),
              "--successor",
              "bundle.json",
            ],
            { cwd: dir, encoding: "utf8" },
          );
        const first = run();
        expect(first.status, first.stderr).to.equal(0);
        expect(first.stdout).to.match(/designated mldsa65-withdrawal-d2/);
        const d2 = JSON.parse(
          readFileSync(join(dir, "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json"), "utf8"),
        );
        const kept = JSON.parse(
          readFileSync(join(dir, "evidence/zk/sp1/designation-evidence/mldsa65-withdrawal-d2.json"), "utf8"),
        );
        expect(kept).to.deep.equal(bundle);
        expect(successorDriftErrors([d1, d2], { [d2.id]: kept })).to.deep.equal([]);
        expect(readFileSync(join(dir, "evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json"), "utf8")).to.equal(
          serializeDesignation(d1),
        );
        // The same bundle again is the same identity: refused, and nothing is overwritten.
        const second = run();
        expect(second.status).to.equal(1);
        expect(second.stderr).to.match(/already designated by mldsa65-withdrawal-d2/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
