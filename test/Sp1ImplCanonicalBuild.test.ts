/**
 * SP1 implementation lane: the canonical build, checked against the designation (scripts/lib/sp1-canonical-build.ts,
 * scripts/sp1-canonical/canonical-build.sh, .github/workflows/sp1-canonical-build.yml).
 *
 * The canonical procedure (SP1-TD1's PINNED_VENDOR_BUILD) runs in a fresh container of the vendor image pinned by
 * digest; the guest lockfile must be the subject's before and after the build (TD1-N7); the ELF and the in-build vkey
 * must be the designation's; and the vkey must be recomputed from the ELF outside the build, with no conflicting
 * result. A changed ELF or vkey is PROGRAM_IDENTITY_DRIFT (STOP: rebuilding the frozen subject must reproduce the
 * designation); a changed image, entrypoint, lockfile or subject is PROCEDURE_DRIFT.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect } from "chai";

import { readDesignations, type ProgramDesignation } from "../scripts/lib/sp1-designation";
import {
  CANONICAL_REBUILD_OBSERVATION_REL,
  canonicalBuildErrors,
  canonicalBuildVerdict,
  collectBuild,
  parseVkeyRecompute,
  type CanonicalBuildObservation,
} from "../scripts/lib/sp1-canonical-build";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

describe("SP1 implementation lane — the canonical build against the designation", function () {
  let d1: ProgramDesignation;
  let committed: CanonicalBuildObservation;

  before(function () {
    d1 = readDesignations(".")[0];
    committed = JSON.parse(readFileSync(resolve(CANONICAL_REBUILD_OBSERVATION_REL), "utf8"));
  });

  it("the committed rebuild of the frozen subject reproduces the designated ELF and vkey, lockfile unchanged", function () {
    expect(canonicalBuildErrors(committed, d1, { minimumHosts: 1 })).to.deep.equal([]);
    expect(canonicalBuildVerdict(committed, d1, { minimumHosts: 1 })).to.equal("REPRODUCED");
    const [b] = committed.builds;
    expect(b.programs["mldsa65-withdrawal"]).to.deep.equal({
      elfSha256: "2adddae753011fb08e30127e38befe99c0092c956e01bf4486ca81827a632d8a",
      elfBytes: 206504,
      vkey: "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc",
    });
    expect([b.guestLockBefore, b.guestLockAfter]).to.deep.equal([
      "87ae1246c7cf2691ab135e0ad8ee79167e23d80aad386b531f7381e9d80f9f48",
      "87ae1246c7cf2691ab135e0ad8ee79167e23d80aad386b531f7381e9d80f9f48",
    ]);
    expect(committed.vkeyRecompute.results).to.deep.include({
      program: "mldsa65-withdrawal",
      elfSha256: "2adddae753011fb08e30127e38befe99c0092c956e01bf4486ca81827a632d8a",
      vkey: "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc",
    });
    // One host here (the workstation); SP1-TD1's designation was established on two, and the workflow rebuilds on two.
    expect(canonicalBuildVerdict(committed, d1, { minimumHosts: 2 })).to.equal("INSUFFICIENT_HOSTS");
  });

  it("collects a build from the driver's outputs, as the driver writes them", function () {
    const dir = mkdtempSync(join(tmpdir(), "sp1-canonical-"));
    try {
      const w = (rel: string, text: string) => {
        mkdirSync(join(dir, rel, ".."), { recursive: true });
        writeFileSync(join(dir, rel), text);
      };
      w("src/git-ids.txt", "abc\nf61fdc6c8785df742857574c5dbf47aa62283c49\n30f72596c430974bf8113892bf41c26dce3629f3\n");
      w("src/guest-lock-at-head.txt", `${"87".repeat(32)}\n`);
      w("image.txt", `sha256:${"aa".repeat(32)} ["${d1.procedure.image}"] linux/amd64\n`);
      w("host-identity.txt", "host_id=x\n");
      w("host/run.log", "...\ncontainer_exit=0\n");
      w("host/env.txt", "build_exit=0 build_seconds=165 started_utc=2026-10-16T15:03:29Z\n");
      w("host/elf-sha256.txt", `${"21".repeat(32)}  mldsa65-withdrawal\n${"22".repeat(32)}  mldsa65-acvp\n`);
      w("host/elf-size.txt", "mldsa65-withdrawal 206504\nmldsa65-acvp 195680\n");
      w("host/vkey.stdout", `{"vkey":"0x${"31".repeat(32)}"}\n`);
      w("host/acvp-vkey.stdout", `{"vkey":"0x${"32".repeat(32)}"}\n`);
      w("host/lock-before.txt", `${"87".repeat(32)}\n`);
      w("host/lock-after.txt", `${"88".repeat(32)}\n`);
      w("host/host-bin-sha256.txt", `${"44".repeat(32)}  /root/out/mldsa65-host\n`);
      w(
        "host/source-sha256.txt",
        `${"51".repeat(32)}  zkvm/guest/Cargo.lock\n${"52".repeat(32)}  zkvm/host/build.rs\n`,
      );
      const b = collectBuild(dir, "github-ubuntu-24.04", d1.procedure);
      expect(b.hostId).to.equal("github-ubuntu-24.04");
      expect(b.containerExit).to.equal(0);
      expect(b.buildSeconds).to.equal(165);
      expect(b.subject).to.deep.include({
        zkvmGuestTree: "f61fdc6c8785df742857574c5dbf47aa62283c49",
        zkvmHostTree: "30f72596c430974bf8113892bf41c26dce3629f3",
        guestLockAtHead: "87".repeat(32),
      });
      expect(b.subject.sourceManifest).to.deep.equal([
        { path: "zkvm/guest/Cargo.lock", sha256: "51".repeat(32) },
        { path: "zkvm/host/build.rs", sha256: "52".repeat(32) },
      ]);
      expect(b.image).to.deep.equal({
        reference: d1.procedure.image,
        id: `sha256:${"aa".repeat(32)}`,
        repoDigests: [d1.procedure.image],
        platform: "linux/amd64",
      });
      expect([b.guestLockBefore, b.guestLockAfter]).to.deep.equal(["87".repeat(32), "88".repeat(32)]);
      expect(b.programs["mldsa65-withdrawal"]).to.deep.equal({
        elfSha256: "21".repeat(32),
        elfBytes: 206504,
        vkey: `0x${"31".repeat(32)}`,
      });
      expect(b.programs["mldsa65-acvp"]).to.deep.equal({
        elfSha256: "22".repeat(32),
        elfBytes: 195680,
        vkey: `0x${"32".repeat(32)}`,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("parses the outside recompute's record", function () {
    const r = parseVkeyRecompute(
      [
        `tool_sha256=${"e2".repeat(32)}`,
        "tool_version=cargo-prove sp1 (8252c29 2026-06-25T11:50:01.543258355Z)",
        "ran_on=Linux 6.18 x86_64 Ubuntu 26.04 LTS AMD Ryzen",
        `elf_mldsa65-withdrawal_sha256=${"21".repeat(32)}`,
        `vkey_output_mldsa65-withdrawal=Verification Key Hash: 0x${"31".repeat(32)} `,
        `elf_mldsa65-acvp_sha256=${"22".repeat(32)}`,
        `vkey_output_mldsa65-acvp=Verification Key Hash: 0x${"32".repeat(32)}`,
      ].join("\n"),
    );
    expect(r).to.deep.equal({
      tool: "cargo-prove sp1 (8252c29 2026-06-25T11:50:01.543258355Z)",
      toolSha256: "e2".repeat(32),
      ranOn: "Linux 6.18 x86_64 Ubuntu 26.04 LTS AMD Ryzen",
      results: [
        { program: "mldsa65-withdrawal", elfSha256: "21".repeat(32), vkey: `0x${"31".repeat(32)}` },
        { program: "mldsa65-acvp", elfSha256: "22".repeat(32), vkey: `0x${"32".repeat(32)}` },
      ],
    });
    // A recompute that printed no key is no result, never a match.
    expect(
      parseVkeyRecompute(
        `elf_mldsa65-withdrawal_sha256=${"21".repeat(32)}\nvkey_output_mldsa65-withdrawal=error: panicked`,
      ).results,
    ).to.deep.equal([]);
  });

  describe("drift is refused, and named", function () {
    const cases: [string, (o: CanonicalBuildObservation) => void, RegExp, string][] = [
      [
        "another ELF",
        (o) => (o.builds[0].programs["mldsa65-withdrawal"].elfSha256 = "00".repeat(32)),
        /ELF/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "another ELF size",
        (o) => (o.builds[0].programs["mldsa65-withdrawal"].elfBytes += 1),
        /ELF/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "another in-build vkey",
        (o) => (o.builds[0].programs["mldsa65-withdrawal"].vkey = `0x${"00".repeat(32)}`),
        /vkey/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "a conflicting outside recompute (one ELF, two vkeys)",
        (o) =>
          o.vkeyRecompute.results.push({
            program: "mldsa65-withdrawal",
            elfSha256: o.builds[0].programs["mldsa65-withdrawal"].elfSha256,
            vkey: `0x${"09".repeat(32)}`,
          }),
        /two vkeys/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      ["no outside recompute", (o) => (o.vkeyRecompute.results = []), /recomputed outside/, "PROGRAM_IDENTITY_DRIFT"],
      [
        "the lockfile changed by the build",
        (o) => (o.builds[0].guestLockAfter = "00".repeat(32)),
        /lockfile/,
        "PROCEDURE_DRIFT",
      ],
      [
        "another lockfile in the subject",
        (o) => (o.builds[0].subject.guestLockAtHead = "00".repeat(32)),
        /lockfile/,
        "PROCEDURE_DRIFT",
      ],
      [
        "a mutable image tag",
        (o) => (o.builds[0].image.repoDigests = ["ghcr.io/succinctlabs/sp1:v6.3.1"]),
        /image/,
        "PROCEDURE_DRIFT",
      ],
      ["another entrypoint", (o) => (o.builds[0].entrypoint.sha256 = "00".repeat(32)), /entrypoint/, "PROCEDURE_DRIFT"],
      ["another subject", (o) => (o.builds[0].subject.zkvmGuestTree = "00".repeat(20)), /subject/, "PROCEDURE_DRIFT"],
      ["another platform", (o) => (o.builds[0].image.platform = "linux/arm64"), /platform/, "PROCEDURE_DRIFT"],
      ["a failed build", (o) => (o.builds[0].containerExit = 101), /exited/, "PROCEDURE_DRIFT"],
    ];
    for (const [label, change, rule, verdict] of cases) {
      it(`refuses ${label} (${verdict})`, function () {
        const o = clone(committed);
        change(o);
        expect(canonicalBuildErrors(o, d1, { minimumHosts: 1 }).join("\n"), label).to.match(rule);
        expect(canonicalBuildVerdict(o, d1, { minimumHosts: 1 }), label).to.equal(verdict);
      });
    }

    it("two hosts must agree with each other and be two hosts", function () {
      const two = clone(committed);
      two.builds.push({ ...clone(two.builds[0]), hostId: "github-ubuntu-22.04" });
      expect(canonicalBuildVerdict(two, d1, { minimumHosts: 2 })).to.equal("REPRODUCED");
      const same = clone(two);
      same.builds[1].hostId = same.builds[0].hostId;
      expect(canonicalBuildErrors(same, d1, { minimumHosts: 2 }).join("\n")).to.match(/2 distinct hosts/);
      const split = clone(two);
      split.builds[1].programs["mldsa65-withdrawal"].elfSha256 = "00".repeat(32);
      expect(canonicalBuildVerdict(split, d1, { minimumHosts: 2 })).to.equal("PROGRAM_IDENTITY_DRIFT");
    });
  });
});
