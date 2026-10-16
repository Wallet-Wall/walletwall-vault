/**
 * SP1 implementation lane: the canonical build, checked against the designation (scripts/lib/sp1-canonical-build.ts,
 * scripts/sp1-canonical/canonical-build.sh, .github/workflows/sp1-canonical-build.yml).
 *
 * The canonical procedure (SP1-TD1's PINNED_VENDOR_BUILD) runs in a fresh container of the vendor image pinned by
 * digest; the guest lockfile must be the subject's before and after the build (TD1-N7); the ELF and the in-build vkey
 * must be the designation's; and the vkey must be recomputed from the ELF outside the build, with no conflicting
 * result. A changed ELF or vkey is PROGRAM_IDENTITY_DRIFT (STOP: rebuilding the frozen subject must reproduce the
 * designation); a changed image, entrypoint, lockfile, subject or driver is PROCEDURE_DRIFT; a record that is absent
 * (a build that failed, an output never copied, a recompute that never ran) is INCOMPLETE: a liveness failure, never
 * read as drift (review finding L-4). Each build names its host, and hosts are distinct machines, not distinct labels
 * (F3). The committed observation is what this tree's checker derives from the committed raw records, written by
 * this tree's driver (F3).
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { expect } from "chai";

import {
  DESIGNATIONS_DIR,
  latestDesignation,
  readDesignations,
  type ProgramDesignation,
} from "../scripts/lib/sp1-designation";
import { workingTreeSourceManifest } from "../scripts/lib/sp1-p1-stop-receipt";
import {
  CANONICAL_BUILD_RECORDS,
  CANONICAL_BUILD_SCHEMA,
  CANONICAL_CHECKER_RELS,
  CANONICAL_DRIVER_REL,
  CANONICAL_REBUILD_OBSERVATION_REL,
  COMMON_MODE,
  canonicalBuildErrors,
  canonicalBuildVerdict,
  canonicalRebuildEvidenceErrors,
  canonicalToolDigests,
  collectBuild,
  conflictingVkeyCount,
  parseVkeyRecompute,
  recordsDirOf,
  type CanonicalBuildObservation,
} from "../scripts/lib/sp1-canonical-build";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const WITHDRAWAL = "mldsa65-withdrawal";
const ACVP = "mldsa65-acvp";

/** A rebuild that reproduces `d` on `hostIds`, each a different machine: the positive control for every refusal. */
function reproducing(d: ProgramDesignation, hostIds: string[]): CanonicalBuildObservation {
  const lock = d.subject.guestCargoLockSha256;
  const driver = "d7".repeat(32);
  const acvp = d.doNotPin.find((x) => x.program === ACVP);
  const manifest = workingTreeSourceManifest(".");
  return {
    schema: CANONICAL_BUILD_SCHEMA,
    measuredAtUtc: "2026-10-16T15:10:00Z",
    designation: d.id,
    tools: {
      driver: { script: CANONICAL_DRIVER_REL, scriptSha256: driver },
      checker: CANONICAL_CHECKER_RELS.map((script) => ({ script, scriptSha256: "c4".repeat(32) })),
    },
    builds: hostIds.map((hostId, i) => ({
      hostId,
      hostIdentity: `host_id=${hostId}\nrunner=runner-${i} runner_os=Linux image_os=ubuntu2${i} image_version=1\nrun=7.1 sha=${"ab".repeat(20)}\nLinux 6.8.${i} x86_64\ncpu=unknown`,
      dockerInfo: "server=28.0.4 kernel=6.8.0 os=Ubuntu 24.04 LTS ncpu=4",
      driver: {
        scriptSha256: driver,
        designation: `${DESIGNATIONS_DIR}/${d.id}.json`,
        startedUtc: "2026-10-16T15:00:00Z",
        finishedUtc: "2026-10-16T15:10:00Z",
      },
      image: {
        reference: d.procedure.image,
        id: `sha256:${"aa".repeat(32)}`,
        repoDigests: [d.procedure.image],
        platform: d.procedure.platform,
      },
      subject: {
        head: "ab".repeat(20),
        zkvmGuestTree: d.subject.zkvmGuestTree,
        zkvmHostTree: d.subject.zkvmHostTree,
        guestLockAtHead: lock,
        sourceManifest: manifest,
      },
      entrypoint: { ...d.procedure.entrypoint },
      containerExit: 0,
      buildSeconds: 165,
      guestLockBefore: lock,
      guestLockAfter: lock,
      programs: {
        [WITHDRAWAL]: { elfSha256: d.elf.sha256, elfBytes: d.elf.bytes, vkey: d.programVKey },
        [ACVP]: {
          elfSha256: acvp?.elfSha256 ?? "22".repeat(32),
          elfBytes: 195680,
          vkey: acvp?.vkey ?? `0x${"32".repeat(32)}`,
        },
      },
      hostBinarySha256: "44".repeat(32),
    })),
    vkeyRecompute: {
      tool: "cargo-prove sp1 (8252c29 2026-06-25T11:50:01.543258355Z)",
      toolSha256: "e2".repeat(32),
      ranOn: "Linux 6.8 x86_64 Ubuntu 24.04 LTS github-hosted",
      results: [{ program: WITHDRAWAL, elfSha256: d.elf.sha256, vkey: d.programVKey }],
    },
    commonMode: [...COMMON_MODE],
  };
}

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
    expect(b.programs[WITHDRAWAL]).to.deep.equal({
      elfSha256: "2adddae753011fb08e30127e38befe99c0092c956e01bf4486ca81827a632d8a",
      elfBytes: 206504,
      vkey: "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc",
    });
    expect([b.guestLockBefore, b.guestLockAfter]).to.deep.equal([
      "87ae1246c7cf2691ab135e0ad8ee79167e23d80aad386b531f7381e9d80f9f48",
      "87ae1246c7cf2691ab135e0ad8ee79167e23d80aad386b531f7381e9d80f9f48",
    ]);
    expect(committed.vkeyRecompute.results).to.deep.include({
      program: WITHDRAWAL,
      elfSha256: "2adddae753011fb08e30127e38befe99c0092c956e01bf4486ca81827a632d8a",
      vkey: "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc",
    });
    // Written by this tree's driver, on the host it names, and re-derivable from the committed raw records.
    expect(b.driver.scriptSha256).to.equal(sha256(readFileSync(resolve(CANONICAL_DRIVER_REL))));
    expect(b.hostIdentity.split("\n")[0]).to.equal(`host_id=${b.hostId}`);
    expect(canonicalRebuildEvidenceErrors(".")).to.deep.equal([]);
    // One host here (the workstation); SP1-TD1's designation was established on two, and the workflow rebuilds on two.
    expect(canonicalBuildVerdict(committed, d1, { minimumHosts: 2 })).to.equal("INSUFFICIENT_HOSTS");
  });

  it("the release rebuild checks the latest designation, whose subject is HEAD's: the driver and the checker default to it", function () {
    const set = readDesignations(".");
    expect(latestDesignation(set)?.id).to.equal(set[set.length - 1].id);
    const successor = { ...clone(set[0]), id: "mldsa65-withdrawal-d2", sequence: 2 };
    expect(latestDesignation([set[0], successor])?.id, "a successor").to.equal("mldsa65-withdrawal-d2");
    expect(latestDesignation([successor, set[0]])?.id, "in any order").to.equal("mldsa65-withdrawal-d2");
    expect(latestDesignation([])).to.equal(undefined);
    const checker = readFileSync(resolve("scripts/check-sp1-canonical-build.ts"), "utf8");
    expect(checker).to.match(/args\("--designation"\)\[0\] \?\? latestDesignation\(designations\)\?\.id/);
    const driver = readFileSync(resolve(CANONICAL_DRIVER_REL), "utf8");
    expect(driver).to.not.match(/mldsa65-withdrawal-d1\.json/);
    expect(driver).to.match(/sequence/);
  });

  it("collects a build from the driver's records: what ran (image, entrypoint, driver) is measured, never copied from the designation", function () {
    const dir = mkdtempSync(join(tmpdir(), "sp1-canonical-"));
    try {
      const w = (rel: string, text: string) => {
        mkdirSync(dirname(join(dir, rel)), { recursive: true });
        writeFileSync(join(dir, rel), text);
      };
      w(
        "driver.txt",
        [
          `driver_sha256=${"d7".repeat(32)}`,
          `designation=${DESIGNATIONS_DIR}/${d1.id}.json`,
          "image=ghcr.io/succinctlabs/sp1:v6.3.1",
          "entrypoint=evidence/zk/sp1-td1/canonical-procedure/host-build-in-container.sh",
          `entrypoint_sha256=${"e7".repeat(32)}`,
          "started_utc=2026-10-16T15:03:00Z",
          "finished_utc=2026-10-16T15:07:00Z",
          "",
        ].join("\n"),
      );
      w("src/git-ids.txt", "abc\nf61fdc6c8785df742857574c5dbf47aa62283c49\n30f72596c430974bf8113892bf41c26dce3629f3\n");
      w("src/guest-lock-at-head.txt", `${"87".repeat(32)}\n`);
      w("image.txt", `sha256:${"aa".repeat(32)} ["ghcr.io/succinctlabs/sp1@sha256:${"bb".repeat(32)}"] linux/amd64\n`);
      w("host-identity.txt", "host_id=github-ubuntu-24.04\nrunner=GitHub Actions 3\n");
      w("host/run.log", "...\ncontainer_exit=0\n");
      w("host/env.txt", "build_exit=0 build_seconds=165 started_utc=2026-10-16T15:03:29Z\n");
      w("host/elf-sha256.txt", `${"21".repeat(32)}  ${WITHDRAWAL}\n${"22".repeat(32)}  ${ACVP}\n`);
      w("host/elf-size.txt", `${WITHDRAWAL} 206504\n${ACVP} 195680\n`);
      w("host/vkey.stdout", `{"vkey":"0x${"31".repeat(32)}"}\n`);
      w("host/acvp-vkey.stdout", `{"vkey":"0x${"32".repeat(32)}"}\n`);
      w("host/lock-before.txt", `${"87".repeat(32)}\n`);
      w("host/lock-after.txt", `${"88".repeat(32)}\n`);
      w("host/host-bin-sha256.txt", `${"44".repeat(32)}  /root/out/mldsa65-host\n`);
      w(
        "host/source-sha256.txt",
        `${"51".repeat(32)}  zkvm/guest/Cargo.lock\n${"52".repeat(32)}  zkvm/host/build.rs\n`,
      );
      const b = collectBuild(dir, "github-ubuntu-24.04");
      expect(b.hostId).to.equal("github-ubuntu-24.04");
      expect(b.hostIdentity).to.equal("host_id=github-ubuntu-24.04\nrunner=GitHub Actions 3");
      expect(b.driver).to.deep.equal({
        scriptSha256: "d7".repeat(32),
        designation: `${DESIGNATIONS_DIR}/${d1.id}.json`,
        startedUtc: "2026-10-16T15:03:00Z",
        finishedUtc: "2026-10-16T15:07:00Z",
      });
      expect(b.containerExit).to.equal(0);
      expect(b.buildSeconds).to.equal(165);
      expect(b.subject).to.deep.include({
        head: "abc",
        zkvmGuestTree: "f61fdc6c8785df742857574c5dbf47aa62283c49",
        zkvmHostTree: "30f72596c430974bf8113892bf41c26dce3629f3",
        guestLockAtHead: "87".repeat(32),
      });
      expect(b.subject.sourceManifest).to.deep.equal([
        { path: "zkvm/guest/Cargo.lock", sha256: "51".repeat(32) },
        { path: "zkvm/host/build.rs", sha256: "52".repeat(32) },
      ]);
      // The image as run (a tag here) and the digests Docker reports for it: the measurement, not the designation.
      expect(b.image).to.deep.equal({
        reference: "ghcr.io/succinctlabs/sp1:v6.3.1",
        id: `sha256:${"aa".repeat(32)}`,
        repoDigests: [`ghcr.io/succinctlabs/sp1@sha256:${"bb".repeat(32)}`],
        platform: "linux/amd64",
      });
      expect(b.entrypoint).to.deep.equal({
        path: "evidence/zk/sp1-td1/canonical-procedure/host-build-in-container.sh",
        sha256: "e7".repeat(32),
      });
      expect([b.guestLockBefore, b.guestLockAfter]).to.deep.equal(["87".repeat(32), "88".repeat(32)]);
      expect(b.programs[WITHDRAWAL]).to.deep.equal({
        elfSha256: "21".repeat(32),
        elfBytes: 206504,
        vkey: `0x${"31".repeat(32)}`,
      });
      expect(b.programs[ACVP]).to.deep.equal({
        elfSha256: "22".repeat(32),
        elfBytes: 195680,
        vkey: `0x${"32".repeat(32)}`,
      });
      expect(
        canonicalBuildErrors({ ...reproducing(d1, ["x"]), builds: [b] }, d1, { minimumHosts: 1 }).join("\n"),
      ).to.match(/did not run the image pinned by digest/);
      // A directory the driver never wrote is a build with no records: incomplete, never drift.
      const none = collectBuild(join(dir, "absent"), "github-ubuntu-22.04");
      const obs = { ...reproducing(d1, ["x"]), builds: [none] };
      expect(canonicalBuildVerdict(obs, d1, { minimumHosts: 1 })).to.equal("INCOMPLETE");
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
        `elf_${WITHDRAWAL}_sha256=${"21".repeat(32)}`,
        `vkey_output_${WITHDRAWAL}=Verification Key Hash: 0x${"31".repeat(32)} `,
        `elf_${ACVP}_sha256=${"22".repeat(32)}`,
        `vkey_output_${ACVP}=Verification Key Hash: 0x${"32".repeat(32)}`,
      ].join("\n"),
    );
    expect(r).to.deep.equal({
      tool: "cargo-prove sp1 (8252c29 2026-06-25T11:50:01.543258355Z)",
      toolSha256: "e2".repeat(32),
      ranOn: "Linux 6.18 x86_64 Ubuntu 26.04 LTS AMD Ryzen",
      results: [
        { program: WITHDRAWAL, elfSha256: "21".repeat(32), vkey: `0x${"31".repeat(32)}` },
        { program: ACVP, elfSha256: "22".repeat(32), vkey: `0x${"32".repeat(32)}` },
      ],
    });
    // A recompute that printed no key is no result, never a match.
    expect(
      parseVkeyRecompute(`elf_${WITHDRAWAL}_sha256=${"21".repeat(32)}\nvkey_output_${WITHDRAWAL}=error: panicked`)
        .results,
    ).to.deep.equal([]);
  });

  describe("drift is refused, and named; an absent record is incomplete, never drift", function () {
    it("a two-host rebuild of distinct machines that reproduces the designation is REPRODUCED (the positive control)", function () {
      const two = reproducing(d1, ["github-ubuntu-24.04", "github-ubuntu-22.04"]);
      expect(canonicalBuildErrors(two, d1, { minimumHosts: 2 })).to.deep.equal([]);
      expect(canonicalBuildVerdict(two, d1, { minimumHosts: 2 })).to.equal("REPRODUCED");
      expect(conflictingVkeyCount(two, d1)).to.equal(0);
    });

    const cases: [string, (o: CanonicalBuildObservation) => void, RegExp, string][] = [
      [
        "another ELF",
        (o) => (o.builds[0].programs[WITHDRAWAL].elfSha256 = "00".repeat(32)),
        /produced ELF/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "another ELF size",
        (o) => (o.builds[0].programs[WITHDRAWAL].elfBytes += 1),
        /produced ELF/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "another in-build vkey",
        (o) => (o.builds[0].programs[WITHDRAWAL].vkey = `0x${"00".repeat(32)}`),
        /in-build vkey/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "a conflicting outside recompute (one ELF, two vkeys)",
        (o) =>
          o.vkeyRecompute.results.push({ program: WITHDRAWAL, elfSha256: d1.elf.sha256, vkey: `0x${"09".repeat(32)}` }),
        /two vkeys/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
      [
        "another ACVP program",
        (o) => (o.builds[0].programs[ACVP].elfSha256 = "00".repeat(32)),
        /ACVP program/,
        "PROGRAM_IDENTITY_DRIFT",
      ],
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
        "a mutable image tag among the digests Docker reports",
        (o) => (o.builds[0].image.repoDigests = ["ghcr.io/succinctlabs/sp1:v6.3.1"]),
        /image/,
        "PROCEDURE_DRIFT",
      ],
      [
        "an image run by a mutable tag",
        (o) => (o.builds[0].image.reference = "ghcr.io/succinctlabs/sp1:v6.3.1"),
        /image/,
        "PROCEDURE_DRIFT",
      ],
      ["another entrypoint", (o) => (o.builds[0].entrypoint.sha256 = "00".repeat(32)), /entrypoint/, "PROCEDURE_DRIFT"],
      ["another subject", (o) => (o.builds[0].subject.zkvmGuestTree = "00".repeat(20)), /subject/, "PROCEDURE_DRIFT"],
      ["another platform", (o) => (o.builds[0].image.platform = "linux/arm64"), /platform/, "PROCEDURE_DRIFT"],
      [
        "another driver",
        (o) => (o.builds[0].driver.scriptSha256 = "00".repeat(32)),
        /another driver/,
        "PROCEDURE_DRIFT",
      ],
      [
        "a build run under another designation",
        (o) => (o.builds[0].driver.designation = `${DESIGNATIONS_DIR}/mldsa65-withdrawal-d9.json`),
        /designation/,
        "PROCEDURE_DRIFT",
      ],
      [
        "a build record that names another host",
        (o) => (o.builds[0].hostIdentity = o.builds[0].hostIdentity.replace(/^host_id=[^\n]*/, "host_id=elsewhere")),
        /names host_id=elsewhere/,
        "PROCEDURE_DRIFT",
      ],
      [
        "a failed build that left nothing",
        (o) => {
          o.builds[0].containerExit = 101;
          o.builds[0].programs = {};
        },
        /did not complete \(container exit 101\)/,
        "INCOMPLETE",
      ],
      [
        "a failed build that left another ELF behind (no identity is judged from a failed build)",
        (o) => {
          o.builds[0].containerExit = 101;
          o.builds[0].programs[WITHDRAWAL].elfSha256 = "00".repeat(32);
        },
        /did not complete/,
        "INCOMPLETE",
      ],
      [
        "a build that exited 0 without its ELF",
        (o) => (o.builds[0].programs[WITHDRAWAL] = { elfSha256: "", elfBytes: 0, vkey: d1.programVKey }),
        /recorded no withdrawal ELF/,
        "INCOMPLETE",
      ],
      [
        "a build that exited 0 without its in-build vkey",
        (o) => (o.builds[0].programs[WITHDRAWAL].vkey = ""),
        /recorded no in-build vkey/,
        "INCOMPLETE",
      ],
      ["a build without its ACVP output", (o) => delete o.builds[0].programs[ACVP], /recorded no ACVP/, "INCOMPLETE"],
      [
        "a missing lockfile record",
        (o) => (o.builds[0].guestLockAfter = ""),
        /recorded no guest lockfile/,
        "INCOMPLETE",
      ],
      [
        "a missing image record (the pull failed)",
        (o) => (o.builds[0].image = { reference: d1.procedure.image, id: "", repoDigests: [], platform: "" }),
        /recorded no image/,
        "INCOMPLETE",
      ],
      [
        "a missing entrypoint record",
        (o) => (o.builds[0].entrypoint.sha256 = ""),
        /recorded no entrypoint/,
        "INCOMPLETE",
      ],
      ["a missing driver record", (o) => (o.builds[0].driver.scriptSha256 = ""), /recorded no driver/, "INCOMPLETE"],
      ["a missing host identity", (o) => (o.builds[0].hostIdentity = ""), /recorded no host identity/, "INCOMPLETE"],
      [
        "no outside recompute (it never ran)",
        (o) => (o.vkeyRecompute.results = []),
        /recomputed outside/,
        "INCOMPLETE",
      ],
      [
        "a recompute that names no tool digest",
        (o) => (o.vkeyRecompute.toolSha256 = ""),
        /no tool digest/,
        "INCOMPLETE",
      ],
      [
        "a recompute of an ELF no build produced (the re-review's L2)",
        (o) => o.vkeyRecompute.results.push({ program: WITHDRAWAL, elfSha256: "ee".repeat(32), vkey: d1.programVKey }),
        /recompute ran on ELF e{64}, which no build produced/,
        "PROCEDURE_DRIFT",
      ],
      [
        "a build that recorded no machine (kernel, CPU, Docker engine)",
        (o) => {
          o.builds[0].hostIdentity = `host_id=${o.builds[0].hostId}\nrunner=r run=1.1`;
          o.builds[0].dockerInfo = "";
        },
        /recorded no machine/,
        "INCOMPLETE",
      ],
    ];
    for (const [label, change, rule, verdict] of cases) {
      it(`refuses ${label} (${verdict})`, function () {
        const o = reproducing(d1, ["host-a"]);
        change(o);
        const errors = canonicalBuildErrors(o, d1, { minimumHosts: 1 }).join("\n");
        expect(errors, label).to.match(rule);
        expect(canonicalBuildVerdict(o, d1, { minimumHosts: 1 }), label).to.equal(verdict);
        if (verdict === "INCOMPLETE") {
          expect(errors, `${label}: an absent record is not drift`).to.not.match(
            /produced ELF|in-build vkey 0x|two vkeys/,
          );
        }
      });
    }

    it("identity drift outranks procedure drift, which outranks an incomplete build, which outranks too few hosts", function () {
      const o = reproducing(d1, ["host-a", "host-b"]);
      o.builds[1].containerExit = 101;
      expect(canonicalBuildVerdict(o, d1, { minimumHosts: 3 }), "incomplete > hosts").to.equal("INCOMPLETE");
      o.builds[0].entrypoint.sha256 = "00".repeat(32);
      expect(canonicalBuildVerdict(o, d1, { minimumHosts: 2 }), "procedure > incomplete").to.equal("PROCEDURE_DRIFT");
      o.builds[0].programs[WITHDRAWAL].vkey = `0x${"00".repeat(32)}`;
      expect(canonicalBuildVerdict(o, d1, { minimumHosts: 2 }), "identity > procedure").to.equal(
        "PROGRAM_IDENTITY_DRIFT",
      );
    });

    it("a conflicting vkey is one that is present and different: a build or a recompute that recorded none is not one", function () {
      const o = reproducing(d1, ["host-a", "host-b"]);
      o.builds[0].programs[WITHDRAWAL].vkey = "";
      o.builds[1].containerExit = 101;
      o.builds[1].programs[WITHDRAWAL].vkey = `0x${"05".repeat(32)}`;
      expect(conflictingVkeyCount(o, d1), "absent, or left by a failed build").to.equal(0);
      o.builds[1].containerExit = 0;
      expect(conflictingVkeyCount(o, d1), "a completed build's other vkey").to.equal(1);
      o.vkeyRecompute.results.push({ program: WITHDRAWAL, elfSha256: d1.elf.sha256, vkey: `0x${"06".repeat(32)}` });
      expect(conflictingVkeyCount(o, d1), "and the recompute's").to.equal(2);
    });

    it("two hosts must agree with each other and be two machines: labels are not hosts", function () {
      const two = reproducing(d1, ["github-ubuntu-24.04", "github-ubuntu-22.04"]);
      const split = clone(two);
      split.builds[1].programs[WITHDRAWAL].elfSha256 = "00".repeat(32);
      expect(canonicalBuildVerdict(split, d1, { minimumHosts: 2 })).to.equal("PROGRAM_IDENTITY_DRIFT");
      expect(canonicalBuildErrors(split, d1, { minimumHosts: 2 }).join("\n")).to.match(/hosts disagree/);
      // The review's falsification (P4): a copy of one host's record under another host id.
      const copied = clone(two);
      copied.builds[1] = { ...clone(copied.builds[0]), hostId: "github-ubuntu-22.04" };
      expect(canonicalBuildErrors(copied, d1, { minimumHosts: 2 }).join("\n")).to.match(
        /names host_id=github-ubuntu-24\.04/,
      );
      expect(canonicalBuildVerdict(copied, d1, { minimumHosts: 2 })).to.not.equal("REPRODUCED");
      // ... and with its host_id line edited to match: still one machine.
      const relabelled = clone(copied);
      relabelled.builds[1].hostIdentity = relabelled.builds[1].hostIdentity.replace(
        /^host_id=[^\n]*/,
        "host_id=github-ubuntu-22.04",
      );
      expect(canonicalBuildErrors(relabelled, d1, { minimumHosts: 2 }).join("\n")).to.match(
        /2 distinct hosts, it has 1/,
      );
      expect(canonicalBuildVerdict(relabelled, d1, { minimumHosts: 2 })).to.equal("INSUFFICIENT_HOSTS");
      // The committed one-host observation with a copied host is no two-host rebuild either.
      const padded = clone(committed);
      padded.builds.push({ ...clone(padded.builds[0]), hostId: "github-ubuntu-22.04" });
      expect(canonicalBuildVerdict(padded, d1, { minimumHosts: 2 })).to.not.equal("REPRODUCED");
    });

    it("one machine is one host whatever its environment names it: only what the driver measured counts (the re-review's A1)", function () {
      // The re-review ran the driver's identity block with RUNNER_NAME=hostB: every measured line was the same.
      const [b] = committed.builds;
      const second = {
        ...clone(b),
        hostId: "host-b",
        hostIdentity: b.hostIdentity
          .replace(/^host_id=[^\n]*/, "host_id=host-b")
          .replace(/^runner=local /m, "runner=hostB ")
          .replace(/^run=unset\.unset/m, "run=4242.1"),
      };
      expect(second.hostIdentity, "the labels differ").to.not.equal(b.hostIdentity);
      const twoLabels = { ...clone(committed), builds: [clone(b), second] };
      expect(canonicalBuildErrors(twoLabels, d1, { minimumHosts: 2 }).join("\n")).to.match(
        /2 distinct hosts, it has 1/,
      );
      expect(canonicalBuildVerdict(twoLabels, d1, { minimumHosts: 2 })).to.equal("INSUFFICIENT_HOSTS");
      // Another machine is another kernel, CPU or Docker engine (the CI runners differ in OS image).
      const otherMachine = {
        ...clone(second),
        dockerInfo: "server=28.0.4 kernel=6.8.0-1017-azure os=Ubuntu 22.04.5 LTS ncpu=4",
      };
      expect(
        canonicalBuildVerdict({ ...clone(committed), builds: [clone(b), otherMachine] }, d1, { minimumHosts: 2 }),
      ).to.equal("REPRODUCED");
    });

    it("an observation that names no driver, or no designation, is refused", function () {
      const o = reproducing(d1, ["host-a"]);
      o.tools.driver.scriptSha256 = "";
      expect(canonicalBuildErrors(o, d1, { minimumHosts: 1 }).join("\n")).to.match(/names no driver/);
      const other = reproducing(d1, ["host-a"]);
      other.designation = "mldsa65-withdrawal-d9";
      expect(canonicalBuildErrors(other, d1, { minimumHosts: 1 }).join("\n")).to.match(/not of designation/);
    });
  });

  describe("the committed observation is bound to the tree's tools and re-derived from the committed raw records (F3)", function () {
    let root: string;
    const copy = (rel: string) => {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      cpSync(resolve(rel), join(root, rel), { recursive: true });
    };
    beforeEach(function () {
      root = mkdtempSync(join(tmpdir(), "sp1-canonical-evidence-"));
      for (const rel of [
        CANONICAL_REBUILD_OBSERVATION_REL,
        recordsDirOf(CANONICAL_REBUILD_OBSERVATION_REL),
        CANONICAL_DRIVER_REL,
        ...CANONICAL_CHECKER_RELS,
        DESIGNATIONS_DIR,
      ]) {
        copy(rel);
      }
    });
    afterEach(function () {
      rmSync(root, { recursive: true, force: true });
    });
    const observationIn = () => JSON.parse(readFileSync(join(root, CANONICAL_REBUILD_OBSERVATION_REL), "utf8"));
    const writeObservation = (o: unknown) =>
      writeFileSync(join(root, CANONICAL_REBUILD_OBSERVATION_REL), `${JSON.stringify(o, null, 2)}\n`);

    it("names the driver and the checker by sha256, as they are in this tree", function () {
      const tools = canonicalToolDigests(".");
      expect(tools.driver).to.deep.equal({
        script: CANONICAL_DRIVER_REL,
        scriptSha256: sha256(readFileSync(resolve(CANONICAL_DRIVER_REL))),
      });
      expect(tools.checker.map((t) => t.script)).to.deep.equal([...CANONICAL_CHECKER_RELS]);
      expect(committed.tools).to.deep.equal(tools);
      expect(CANONICAL_CHECKER_RELS).to.include.members([
        "scripts/check-sp1-canonical-build.ts",
        "scripts/lib/sp1-canonical-build.ts",
      ]);
      // The raw records are committed next to the observation, one directory per host.
      expect(readdirSync(join(resolve(recordsDirOf(CANONICAL_REBUILD_OBSERVATION_REL)), "builds"))).to.deep.equal(
        committed.builds.map((b) => b.hostId),
      );
    });

    it("every raw record is committed: none is ignored, so a fresh clone re-derives what this checkout does", function () {
      const records = recordsDirOf(CANONICAL_REBUILD_OBSERVATION_REL);
      const git = (...args: string[]) =>
        execFileSync("git", args, { encoding: "utf8" }).split("\n").filter(Boolean).sort();
      expect(git("ls-files", "--others", "--ignored", "--exclude-standard", "--", records), "ignored").to.deep.equal(
        [],
      );
      expect(git("ls-files", "--others", "--exclude-standard", "--", records), "untracked").to.deep.equal([]);
      const tracked = git("ls-files", "--", records);
      for (const b of committed.builds) {
        for (const rel of CANONICAL_BUILD_RECORDS) {
          expect(tracked, `${b.hostId}: ${rel}`).to.include(`${records}/builds/${b.hostId}/${rel}`);
        }
      }
    });

    it("the copied evidence validates (the positive control for the tampering below)", function () {
      expect(canonicalRebuildEvidenceErrors(root)).to.deep.equal([]);
    });

    it("refuses a hand-edited observation: a host appended, a value changed", function () {
      const o = observationIn();
      o.builds.push({ ...clone(o.builds[0]), hostId: "github-ubuntu-22.04" });
      writeObservation(o);
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(
        /not what .* derives from the committed raw records/,
      );
      const v = observationIn();
      v.builds.pop();
      v.builds[0].programs[WITHDRAWAL].elfBytes += 1;
      writeObservation(v);
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(
        /not what .* derives from the committed raw records/,
      );
    });

    it("refuses an edited raw record", function () {
      const records = recordsDirOf(CANONICAL_REBUILD_OBSERVATION_REL);
      const sizes = join(root, records, "builds", committed.builds[0].hostId, "host/elf-size.txt");
      writeFileSync(sizes, readFileSync(sizes, "utf8").replace("206504", "206505"));
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(
        /not what .* derives from the committed raw records/,
      );
    });

    it("refuses an observation the tree's driver or checker did not write: change either and re-run", function () {
      writeFileSync(
        join(root, CANONICAL_DRIVER_REL),
        `${readFileSync(join(root, CANONICAL_DRIVER_REL), "utf8")}# edited\n`,
      );
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(/driver .* is not this tree's/);
      copy(CANONICAL_DRIVER_REL);
      const lib = join(root, CANONICAL_CHECKER_RELS[1]);
      writeFileSync(lib, `${readFileSync(lib, "utf8")}// edited\n`);
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(/checker .* is not this tree's/);
    });

    it("refuses a missing record directory or observation: no evidence is not evidence of a rebuild", function () {
      rmSync(join(root, recordsDirOf(CANONICAL_REBUILD_OBSERVATION_REL)), { recursive: true, force: true });
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(/raw records/);
      rmSync(join(root, CANONICAL_REBUILD_OBSERVATION_REL));
      expect(canonicalRebuildEvidenceErrors(root).join("\n")).to.match(/no observation|cannot read/);
    });
  });
});
