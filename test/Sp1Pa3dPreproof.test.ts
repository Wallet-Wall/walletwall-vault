/**
 * SP1-PA3D: the pre-proof environment attestation (scripts/lib/sp1-pa3d-exercise.ts, scripts/sp1-pa3d-preproof.ts).
 * On the proving host, before the one authorized proof, the tool records facts (the manifest's validity and digest,
 * both checkouts, the installed circuit, the host binary, the gnark image, the re-derived observer qualification, the
 * platform) and the verdict is a pure function of those facts and the manifest: PA3D_PREPROOF_ENVIRONMENT_VALID or
 * PA3D_PREPROOF_ENVIRONMENT_REFUSED, each refusal named. The validator recomputes the verdict from the recorded facts
 * (a measurement never grades itself). Offline: no kernel, docker, network, SP1 or proof. Research prototype. Not
 * audited.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

import { MANIFEST_REL, manifestContextFromRepo, type Manifest } from "../scripts/lib/sp1-pa3d-exercise";
import {
  MIN_RAM_KIB,
  MIN_RAM_PLUS_SWAP_KIB,
  PREPROOF_SCHEMA,
  preproofErrors,
  preproofExpectationsOf,
  preproofObservationRel,
  preproofVerdictOf,
  serializePreproof,
  type PreproofFacts,
  type PreproofObservation,
} from "../scripts/lib/sp1-pa3d-preproof";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

const ctx = manifestContextFromRepo(".");
const manifestText = lf(readFileSync(MANIFEST_REL, "utf8"));
const manifest = JSON.parse(manifestText) as Manifest;
const expected = preproofExpectationsOf(manifest, manifestText);

/** Facts that satisfy every expectation of the committed manifest: the proving host as it should be. */
function validFacts(): PreproofFacts {
  return {
    schema: PREPROOF_SCHEMA,
    lane: "SP1-PA3D",
    host: manifest.environment.hostLabel,
    measuredAtUtc: "2026-11-02T04:00:00Z",
    manifest: { path: MANIFEST_REL, sha256: expected.manifestSha256, errors: [] },
    laneCheckout: { commit: "a".repeat(40), dirty: false },
    provingCheckout: {
      path: "/home/prover/pa3d-src",
      commit: manifest.source.commit,
      dirty: false,
      tools: manifest.tools.map((t) => ({ ...t })),
    },
    circuit: {
      root: "/home/prover/pa3b/circuit-root",
      members: manifest.circuit.members.map((m) => ({ ...m })),
      error: null,
    },
    hostBinary: {
      path: "/home/prover/pa3b/bin/mldsa65-host",
      bytes: 57567008,
      sha256: manifest.prover.hostBinary.sha256,
    },
    gnark: {
      imageRef: manifest.circuit.gnark.imageRef,
      localRepoDigests: [manifest.circuit.gnark.imageRef],
      error: null,
    },
    qualification: {
      path: manifest.environment.qualification.path,
      sha256: manifest.environment.qualification.sha256,
      errors: [],
    },
    platform: {
      os: "linux",
      kernel: "6.18.33.1-microsoft-standard-WSL2",
      machine: "x86_64",
      bootId: "b6a0c805-601b-4c94-936f-4ac597790444",
      distro: "Ubuntu 24.04.4 LTS",
      memTotalKiB: 24608408,
      swapTotalKiB: 41943040,
      node: "v24.16.0",
      docker: "29.1.3 api=1.52 endpoint=unix:///var/run/docker.sock",
      user: "prover",
      uid: 1001,
    },
  };
}

const refusalsOf = (edit: (f: PreproofFacts) => void): string[] => {
  const f = validFacts();
  edit(f);
  const v = preproofVerdictOf(f, expected);
  expect(v.verdict).to.equal("PA3D_PREPROOF_ENVIRONMENT_REFUSED");
  return v.refusals;
};

describe("SP1-PA3D — the pre-proof environment attestation", function () {
  this.timeout(60_000);

  it("names its schema and the observation file by host label", function () {
    expect(PREPROOF_SCHEMA).to.equal("walletwall.sp1-pa3d-preproof-attestation.v1");
    expect(preproofObservationRel("developer-workstation-wsl2")).to.equal(
      "evidence/zk/sp1-impl/observations/pa3d-preproof-developer-workstation-wsl2.raw.json",
    );
    expect(MIN_RAM_KIB).to.equal(16 * 1024 * 1024);
    expect(MIN_RAM_PLUS_SWAP_KIB).to.equal(40 * 1024 * 1024);
  });

  it("takes its expectations from the committed manifest: its digest, source, tools, members, binary, image, qualification", function () {
    expect(expected.manifestSha256).to.equal(sha256(manifestText));
    expect(expected.sourceCommit).to.equal(manifest.source.commit);
    expect(expected.hostLabel).to.equal(manifest.environment.hostLabel);
    expect(expected.tools).to.deep.equal(manifest.tools);
    expect(expected.members).to.deep.equal(manifest.circuit.members);
    expect(expected.hostBinarySha256).to.equal(manifest.prover.hostBinary.sha256);
    expect(expected.gnarkImageRef).to.equal(manifest.circuit.gnark.imageRef);
    expect(expected.qualificationSha256).to.equal(manifest.environment.qualification.sha256);
  });

  it("is VALID when every fact meets the manifest and the host is an unprivileged Linux with enough memory", function () {
    expect(preproofVerdictOf(validFacts(), expected)).to.deep.equal({
      verdict: "PA3D_PREPROOF_ENVIRONMENT_VALID",
      refusals: [],
    });
  });

  it("refuses an invalid or different manifest, or another host label", function () {
    expect(refusalsOf((f) => f.manifest.errors.push("LEAF_DIFFERS x")).join("\n")).to.include("MANIFEST_INVALID");
    expect(refusalsOf((f) => (f.manifest.sha256 = "00".repeat(32))).join("\n")).to.include("MANIFEST_DIFFERS");
    expect(refusalsOf((f) => (f.host = "another-host")).join("\n")).to.include("HOST_LABEL_DIFFERS");
  });

  it("refuses a dirty lane checkout and a proving checkout that is not a clean checkout of the source commit", function () {
    expect(refusalsOf((f) => (f.laneCheckout.dirty = true)).join("\n")).to.include("LANE_CHECKOUT_DIRTY");
    expect(refusalsOf((f) => (f.provingCheckout.dirty = true)).join("\n")).to.include("PROVING_CHECKOUT_DIRTY");
    expect(refusalsOf((f) => (f.provingCheckout.commit = "b".repeat(40))).join("\n")).to.include(
      "PROVING_CHECKOUT_NOT_AT_SOURCE",
    );
  });

  it("refuses a proving checkout whose run tools differ from the manifest's, by one byte, one file or one extra", function () {
    expect(refusalsOf((f) => (f.provingCheckout.tools[0].sha256 = "00".repeat(32))).join("\n")).to.include(
      "PROVING_CHECKOUT_TOOL_DRIFT",
    );
    expect(refusalsOf((f) => f.provingCheckout.tools.pop()).join("\n")).to.include("PROVING_CHECKOUT_TOOL_DRIFT");
    expect(
      refusalsOf((f) => f.provingCheckout.tools.push({ path: "scripts/extra.ts", sha256: "11".repeat(32) })).join("\n"),
    ).to.include("PROVING_CHECKOUT_TOOL_DRIFT");
  });

  it("refuses an installed circuit the gate's own check refuses, or whose members are not the record's", function () {
    expect(refusalsOf((f) => (f.circuit.error = "CIRCUIT_INTEGRITY_FAILED: x")).join("\n")).to.include(
      "CIRCUIT_NOT_VERIFIED",
    );
    expect(refusalsOf((f) => (f.circuit.members = null)).join("\n")).to.include("CIRCUIT_NOT_VERIFIED");
    expect(
      refusalsOf((f) => ((f.circuit.members as { sha256: string }[])[2].sha256 = "00".repeat(32))).join("\n"),
    ).to.include("CIRCUIT_MEMBERS_DIFFER");
    expect(refusalsOf((f) => (f.circuit.members as unknown[]).pop()).join("\n")).to.include("CIRCUIT_MEMBERS_DIFFER");
  });

  it("refuses a host binary that is not the canonical build's, and a gnark image that is not local by digest", function () {
    expect(refusalsOf((f) => (f.hostBinary.sha256 = "00".repeat(32))).join("\n")).to.include("HOST_BINARY_DIFFERS");
    expect(refusalsOf((f) => (f.hostBinary.sha256 = null)).join("\n")).to.include("HOST_BINARY_DIFFERS");
    expect(refusalsOf((f) => (f.gnark.localRepoDigests = null)).join("\n")).to.include("GNARK_IMAGE_ABSENT");
    expect(
      refusalsOf((f) => (f.gnark.localRepoDigests = ["ghcr.io/x@sha256:" + "00".repeat(32)])).join("\n"),
    ).to.include("GNARK_IMAGE_ABSENT");
    expect(refusalsOf((f) => (f.gnark.error = "docker did not run")).join("\n")).to.include("GNARK_IMAGE_ABSENT");
  });

  it("refuses an observer qualification that does not re-derive here, or that is not the manifest's", function () {
    expect(refusalsOf((f) => f.qualification.errors.push("x")).join("\n")).to.include("OBSERVER_QUALIFICATION_INVALID");
    expect(refusalsOf((f) => (f.qualification.sha256 = "00".repeat(32))).join("\n")).to.include(
      "OBSERVER_QUALIFICATION_DIFFERS",
    );
  });

  it("refuses a host that is not Linux, runs the tool as root, lacks docker or lacks memory", function () {
    expect(refusalsOf((f) => (f.platform.os = "win32")).join("\n")).to.include("NOT_LINUX");
    expect(refusalsOf((f) => (f.platform.uid = 0)).join("\n")).to.include("RUNS_AS_ROOT");
    expect(refusalsOf((f) => (f.platform.docker = null)).join("\n")).to.include("DOCKER_UNAVAILABLE");
    expect(refusalsOf((f) => (f.platform.memTotalKiB = MIN_RAM_KIB - 1)).join("\n")).to.include("MEMORY_INSUFFICIENT");
    expect(
      refusalsOf((f) => {
        f.platform.memTotalKiB = MIN_RAM_KIB;
        f.platform.swapTotalKiB = MIN_RAM_PLUS_SWAP_KIB - MIN_RAM_KIB - 1;
      }).join("\n"),
    ).to.include("MEMORY_INSUFFICIENT");
  });

  it("lists every refusal at once, never only the first", function () {
    const refusals = refusalsOf((f) => {
      f.platform.uid = 0;
      f.hostBinary.sha256 = null;
      f.provingCheckout.dirty = true;
    });
    expect(refusals.length).to.equal(3);
  });

  describe("the validator of a committed attestation", function () {
    const observation = (edit: (o: PreproofObservation) => void = () => {}): PreproofObservation => {
      const facts = validFacts();
      const o: PreproofObservation = { ...facts, ...preproofVerdictOf(facts, expected) };
      edit(o);
      return o;
    };

    it("accepts an observation whose recorded verdict is what its facts and the committed manifest derive", function () {
      const text = serializePreproof(observation());
      expect(text.endsWith("}\n")).to.equal(true);
      expect(preproofErrors(JSON.parse(text), ctx)).to.deep.equal([]);
    });

    it("refuses a verdict that is not what the facts derive: VALID over refusing facts, or refusals edited away", function () {
      const graded = observation((o) => {
        o.platform.uid = 0;
      });
      expect(graded.verdict).to.equal("PA3D_PREPROOF_ENVIRONMENT_VALID");
      expect(preproofErrors(graded, ctx).join("\n")).to.include("VERDICT_DIFFERS");
      const trimmed = observation((o) => {
        o.hostBinary.sha256 = null;
      });
      expect(preproofErrors(trimmed, ctx).join("\n")).to.include("VERDICT_DIFFERS");
      const honest = observation();
      honest.hostBinary.sha256 = null;
      Object.assign(honest, preproofVerdictOf(honest, expected));
      expect(honest.verdict).to.equal("PA3D_PREPROOF_ENVIRONMENT_REFUSED");
      expect(preproofErrors(honest, ctx)).to.deep.equal([]);
    });

    it("refuses what is not an attestation", function () {
      expect(preproofErrors(null, ctx)).to.not.deep.equal([]);
      expect(
        preproofErrors(
          observation((o) => ((o as { schema: string }).schema = "x")),
          ctx,
        ).join("\n"),
      ).to.include("SCHEMA");
      expect(preproofErrors({ ...observation(), extra: 1 }, ctx).join("\n")).to.include("extra");
      const fewer = clone(observation()) as Partial<PreproofObservation>;
      delete fewer.platform;
      expect(preproofErrors(fewer, ctx).join("\n")).to.include("platform");
      expect(
        preproofErrors(
          observation((o) => (o.measuredAtUtc = "now")),
          ctx,
        ).join("\n"),
      ).to.include("MEASURED_AT");
    });
  });

  describe("the committed attestation", function () {
    const rel = preproofObservationRel(manifest.environment.hostLabel);

    it("when committed, is VALID and what its facts derive; it records the host as unprivileged Linux", function () {
      if (!existsSync(rel)) this.skip();
      const committed = JSON.parse(lf(readFileSync(rel, "utf8"))) as PreproofObservation;
      expect(preproofErrors(committed, ctx)).to.deep.equal([]);
      expect(committed.verdict).to.equal("PA3D_PREPROOF_ENVIRONMENT_VALID");
      expect(committed.platform.os).to.equal("linux");
      expect(committed.platform.uid).to.not.equal(0);
      expect(committed.provingCheckout.commit).to.equal(manifest.source.commit);
      expect(committed.manifest.sha256).to.equal(sha256(manifestText));
    });
  });
});
