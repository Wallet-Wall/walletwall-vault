/**
 * SP1-PA3D: the exercise manifest (scripts/lib/sp1-pa3d-exercise.ts), authored before the one authorized proof and
 * derived from committed facts only: the proof statement (program, ELF, inputs, expected public values), the circuit and
 * verifier identities, the prover's implementation and toolchain, the environment and the observer qualification it
 * stands on, the tools the run's checkout must hold unchanged, the acquisition gate over every artifact the proof needs,
 * and the operator's authorization marker. The validator re-derives the manifest from its own operator inputs and the
 * checkout (a measurement never grades itself). Offline: no kernel, docker, network, SP1 or proof. Research prototype.
 * Not audited.
 */
import { expect } from "chai";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { QUALIFICATION_REL } from "../scripts/lib/sp1-observer-qualification";
import {
  ACQUISITION_PASSING_CLASSES,
  EXPECTED_PUBLIC_VALUES_SOURCE_REL,
  FINAL_STATES,
  GUEST_MANIFEST_REL,
  HOST_LOCKFILE_REL,
  LANE,
  MANIFEST_JSON_SCHEMA_REL,
  MANIFEST_REL,
  MANIFEST_SCHEMA,
  NEXT_LANE,
  NOT_AUTHORIZED,
  PRODUCTION_SP1_BINDING,
  REPOSITORY_ID,
  RUN_TOOLS,
  TOOLCHAIN_ENV_REL,
  acquisitionGateOf,
  manifestContextFromRepo,
  manifestErrors,
  manifestFrom,
  manifestInputsOf,
  serializeManifest,
  sp1VersionsOf,
  toolchainOf,
  type Artifact,
  type Manifest,
  type ManifestContext,
  type ManifestInputs,
} from "../scripts/lib/sp1-pa3d-exercise";
import { ATTRIBUTED_RUN_SCRIPT_REL, VERIFICATION_SCRIPT_REL } from "../scripts/lib/sp1-proof-exercise";
import { OBSERVER_SCRIPT_REL } from "../scripts/sp1-egress-observer";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

/** The real checkout, with some files replaced (null removes one) and some blobs at the source commit replaced. */
function withFiles(
  ctx: ManifestContext,
  files: Record<string, string | null>,
  blobs: Record<string, string | null> = {},
): ManifestContext {
  return {
    ...ctx,
    readFile: (rel) =>
      rel in files ? (files[rel] === null ? null : Buffer.from(files[rel] as string)) : ctx.readFile(rel),
    blobAt: (commit, rel) =>
      rel in blobs ? (blobs[rel] === null ? null : Buffer.from(blobs[rel] as string)) : ctx.blobAt(commit, rel),
  };
}

const ctx = manifestContextFromRepo(".");
const INPUTS: ManifestInputs = {
  sourceCommit: ctx.headCommit,
  hostLabel: "developer-workstation-wsl2",
  environment: {
    kind: "wsl2-ubuntu-24.04",
    description: "a WSL2 Ubuntu 24.04 virtual machine with the distribution's own Docker Engine",
  },
  startedAtUtc: "2026-11-02T03:00:00Z",
  authorization: {
    by: "OWNER",
    proofs: 1,
    words: "exactly one controlled v2 attributed proof",
    recordedAtUtc: "2026-11-02T02:40:00Z",
  },
};

describe("SP1-PA3D — the exercise manifest", function () {
  this.timeout(60_000);

  describe("the constants", function () {
    it("names the lane, its successor, the record and the five final states", function () {
      expect(LANE).to.equal("SP1-PA3D");
      expect(NEXT_LANE).to.equal("SP1-PA3E");
      expect(REPOSITORY_ID).to.equal("Wallet-Wall/walletwall-vault");
      expect(PRODUCTION_SP1_BINDING).to.equal("NOT_ESTABLISHED");
      expect(MANIFEST_SCHEMA).to.equal("walletwall.sp1-pa3d-exercise-manifest.v1");
      expect(MANIFEST_REL).to.equal("evidence/zk/sp1-impl/pa3d-exercise-manifest.json");
      expect([...FINAL_STATES]).to.deep.equal([
        "PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED",
        "PA3D_PROOF_GENERATED_VERIFICATION_BLOCKED",
        "PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE",
        "PA3D_PREPROOF_ENVIRONMENT_REFUSED",
        "PA3D_PROVING_FAILED",
      ]);
      expect(NOT_AUTHORIZED).to.include("third-party hosted proving");
      expect(NOT_AUTHORIZED).to.include("production proving");
      expect(RUN_TOOLS).to.include(ATTRIBUTED_RUN_SCRIPT_REL);
      expect(RUN_TOOLS).to.include(OBSERVER_SCRIPT_REL);
      expect(RUN_TOOLS).to.include(VERIFICATION_SCRIPT_REL);
      expect(RUN_TOOLS).to.include("scripts/lib/sp1-prove-gate.ts");
    });
  });

  describe("the toolchain and SP1 versions", function () {
    it("reads rustc and cargo from the committed canonical-build environment log", function () {
      const tc = toolchainOf(lf(readFileSync(TOOLCHAIN_ENV_REL, "utf8")));
      expect(tc).to.deep.equal({
        rustc: "1.96.0 (ac68faa20 2026-05-25)",
        cargo: "1.96.0 (30a34c682 2026-05-25)",
      });
      expect(toolchainOf("env=x\nbinary: rustc\n")).to.equal(null);
      expect(toolchainOf("rustc 1.96.0 (ac68faa20 2026-05-25)\n")).to.equal(null);
    });

    it("reads the pinned sp1-sdk and sp1-zkvm versions from the host lockfile and the guest manifest", function () {
      const v = sp1VersionsOf(
        lf(readFileSync(HOST_LOCKFILE_REL, "utf8")),
        lf(readFileSync(GUEST_MANIFEST_REL, "utf8")),
      );
      expect(v).to.deep.equal({ sdk: "6.3.1", zkvm: "6.3.1" });
      expect(sp1VersionsOf('[[package]]\nname = "other"\nversion = "1.0.0"\n', "[dependencies]\n")).to.deep.equal({
        sdk: null,
        zkvm: null,
      });
      expect(sp1VersionsOf("", 'sp1-zkvm = { version = "=6.3.1", features = ["x"] }\n').zkvm).to.equal("6.3.1");
    });
  });

  describe("the acquisition gate", function () {
    const ok = (over: Partial<Artifact> = {}): Artifact => ({
      name: "a pinned thing",
      class: "digest-pinned",
      identity: "sha256:" + "ab".repeat(32),
      pinnedBy: "evidence/x.json",
      acquisition: "NONE",
      verifiedBy: "its digest, before the proof",
      ...over,
    });

    it("passes only when every artifact is pinned or host-recorded and none must be acquired", function () {
      expect(
        acquisitionGateOf([ok(), ok({ class: "repository-pinned" }), ok({ class: "host-dependent" })]),
      ).to.deep.equal({ verdict: "PASSED", blockers: [] });
      expect([...ACQUISITION_PASSING_CLASSES]).to.deep.equal([
        "repository-pinned",
        "digest-pinned",
        "version-pinned",
        "host-dependent",
      ]);
    });

    it("blocks a network-dependent, mutable or unknown artifact, naming it", function () {
      for (const cls of ["network-dependent", "mutable-external-dependency", "unknown-unverified"] as const) {
        const gate = acquisitionGateOf([ok(), ok({ name: "the suspect", class: cls })]);
        expect(gate.verdict).to.equal("BLOCKED");
        expect(gate.blockers).to.have.length(1);
        expect(gate.blockers[0]).to.include("the suspect");
        expect(gate.blockers[0]).to.include(cls);
      }
    });

    it("blocks an artifact that would have to be acquired, whatever its class", function () {
      const gate = acquisitionGateOf([ok({ name: "fetched", acquisition: "DOWNLOAD" as Artifact["acquisition"] })]);
      expect(gate.verdict).to.equal("BLOCKED");
      expect(gate.blockers[0]).to.include("fetched");
      expect(gate.blockers[0]).to.include("DOWNLOAD");
      expect(acquisitionGateOf([]).verdict).to.equal("BLOCKED");
    });
  });

  describe("the derivation from the checkout", function () {
    const m = manifestFrom(ctx, INPUTS);

    it("binds the lane, the source commit, its version and parents, and the operator's inputs verbatim", function () {
      expect(m.schema).to.equal(MANIFEST_SCHEMA);
      expect(m.lane).to.equal(LANE);
      expect(m.repository).to.equal(REPOSITORY_ID);
      expect(m.productionSp1Binding).to.equal(PRODUCTION_SP1_BINDING);
      expect(m.source.commit).to.equal(ctx.headCommit);
      expect(m.source.version).to.equal(JSON.parse(readFileSync("package.json", "utf8")).version);
      expect(m.source.parents.length).to.be.greaterThan(0);
      for (const p of m.source.parents) expect(p).to.match(/^[0-9a-f]{40}$/);
      expect(m.startedAtUtc).to.equal(INPUTS.startedAtUtc);
      expect(m.authorization).to.deep.equal({ ...INPUTS.authorization, notAuthorized: [...NOT_AUTHORIZED] });
      expect(m.environment.hostLabel).to.equal(INPUTS.hostLabel);
      expect(m.environment.kind).to.equal(INPUTS.environment.kind);
      expect(m.environment.description).to.equal(INPUTS.environment.description);
      expect(manifestInputsOf(m)).to.deep.equal(INPUTS);
    });

    it("states the proof: the designated program, its ELF, the committed inputs and the expected public values", function () {
      const d = JSON.parse(readFileSync(`evidence/zk/sp1/designations/${ctx.anchor.designation}.json`, "utf8"));
      expect(m.statement.designation).to.equal(d.id);
      expect(m.statement.program).to.equal(d.program);
      expect(m.statement.programVKey).to.equal(d.programVKey);
      expect(m.statement.guestElf).to.deep.equal(d.elf);
      expect(m.statement.zkvmGuestTree).to.equal(d.subject.zkvmGuestTree);
      expect(m.statement.zkvmHostTree).to.equal(d.subject.zkvmHostTree);
      const inputs = readFileSync("zkvm/fixtures/mldsa65-withdrawal.inputs.json");
      expect(m.statement.inputs).to.deep.equal({
        path: "zkvm/fixtures/mldsa65-withdrawal.inputs.json",
        bytes: inputs.length,
        sha256: sha256(inputs),
      });
      const v1 = JSON.parse(readFileSync(EXPECTED_PUBLIC_VALUES_SOURCE_REL, "utf8"));
      expect(m.statement.expectedPublicValues.hex).to.equal(v1.proof.publicValues);
      expect(m.statement.expectedPublicValues.sha256).to.equal(
        sha256(Buffer.from(v1.proof.publicValues.slice(2), "hex")),
      );
      expect(m.statement.expectedPublicValues.source.path).to.equal(EXPECTED_PUBLIC_VALUES_SOURCE_REL);
      expect(m.statement.text).to.include(d.elf.sha256);
      expect(m.statement.text).to.include(m.statement.expectedPublicValues.sha256);
      expect(m.statement.text).to.include(d.programVKey);
      expect(m.statement.text).to.include("no production binding");
    });

    it("binds the circuit, its members, the gnark image and the verifier as the archive record and designation hold them", function () {
      const record = JSON.parse(readFileSync(m.circuit.archiveRecord.path, "utf8"));
      expect(m.circuit.version).to.equal(ctx.anchor.circuitVersion);
      expect(m.circuit.archiveRecord.sha256).to.equal(sha256(lf(readFileSync(m.circuit.archiveRecord.path, "utf8"))));
      expect(m.circuit.archive).to.deep.equal({
        file: record.archive.file,
        bytes: record.archive.bytes,
        sha256: record.archive.sha256,
        sourceUrl: record.archive.sourceUrl,
        sourceUrlRole: "PROVENANCE_ONLY",
      });
      expect(m.circuit.members).to.deep.equal(record.members);
      expect(m.circuit.gnark).to.deep.equal({
        repository: record.gnark.repository,
        digest: record.gnark.digest,
        imageRef: `${record.gnark.repository}@${record.gnark.digest}`,
      });
      expect(m.circuit.verifier.version).to.equal(ctx.anchor.verifier.version);
      expect(m.circuit.verifier.verifierHash).to.equal(ctx.anchor.verifier.verifierHash);
      expect(m.circuit.verifier.selector).to.equal(ctx.anchor.verifier.verifierHash.slice(0, 10));
      expect(m.circuit.verifier.address).to.match(/^0x[0-9a-fA-F]{40}$/);
    });

    it("binds the prover: the canonical host binary, the SP1 release, the Rust toolchain and the cpu mode", function () {
      expect(m.prover.mode).to.equal("cpu");
      expect(m.prover.proofSystem).to.equal("groth16");
      expect(m.prover.hostBinary.sha256).to.match(/^[0-9a-f]{64}$/);
      expect(m.prover.hostBinary.pinnedBy).to.include("canonical-rebuild");
      expect(m.prover.sp1).to.deep.equal({ sdk: "6.3.1", zkvm: "6.3.1" });
      expect(m.prover.rust).to.deep.equal({
        rustc: "1.96.0 (ac68faa20 2026-05-25)",
        cargo: "1.96.0 (30a34c682 2026-05-25)",
        source: TOOLCHAIN_ENV_REL,
      });
      expect(m.prover.buildImage.reference).to.match(/^ghcr\.io\/succinctlabs\/sp1@sha256:[0-9a-f]{64}$/);
      expect(m.prover.frozenEnv).to.deep.equal([
        "SP1_PROVER",
        "SP1_GROTH16_CIRCUIT_PATH",
        "SP1_GNARK_IMAGE",
        "DOCKER_CONTEXT",
      ]);
    });

    it("stands on the committed observer qualification, bound by digest and state", function () {
      const q = JSON.parse(readFileSync(QUALIFICATION_REL, "utf8"));
      expect(m.environment.qualification).to.deep.equal({
        lane: "SP1-PA3C-Q1",
        path: QUALIFICATION_REL,
        sha256: sha256(lf(readFileSync(QUALIFICATION_REL, "utf8"))),
        state: "OBSERVER_QUALIFIED_FOR_PA3D",
        qualifiedAtUtc: q.qualifiedAtUtc,
        observerScriptSha256: q.source.observerScriptSha256,
      });
      expect(m.environment.qualification.observerScriptSha256).to.equal(
        sha256(lf(readFileSync(OBSERVER_SCRIPT_REL, "utf8"))),
      );
    });

    it("refuses to be authored on an observer that is not qualified for this lane", function () {
      const q = JSON.parse(readFileSync(QUALIFICATION_REL, "utf8"));
      const blocked = { ...q, state: "OBSERVER_QUALIFICATION_BLOCKED", blockers: ["x"], next: null };
      assert.throws(
        () => manifestFrom(withFiles(ctx, { [QUALIFICATION_REL]: JSON.stringify(blocked) }), INPUTS),
        /OBSERVER_NOT_QUALIFIED/,
      );
      const other = { ...q, next: { ...q.next, lane: "SP1-PA3Z" } };
      assert.throws(
        () => manifestFrom(withFiles(ctx, { [QUALIFICATION_REL]: JSON.stringify(other) }), INPUTS),
        /OBSERVER_NOT_QUALIFIED/,
      );
      assert.throws(
        () => manifestFrom(withFiles(ctx, { [QUALIFICATION_REL]: null }), INPUTS),
        /QUALIFICATION_REL|missing/,
      );
    });

    it("binds every run tool at the source commit and requires the checkout to hold the same bytes", function () {
      expect(m.tools.map((t) => t.path)).to.deep.equal([...RUN_TOOLS]);
      for (const t of m.tools) expect(t.sha256).to.equal(sha256(lf(readFileSync(t.path, "utf8"))));
      const drifted = withFiles(ctx, {}, { [OBSERVER_SCRIPT_REL]: "// another observer\n" });
      assert.throws(() => manifestFrom(drifted, INPUTS), /TOOL_DRIFT/);
      const absent = withFiles(ctx, {}, { "scripts/lib/sp1-prove-gate.ts": null });
      assert.throws(() => manifestFrom(absent, INPUTS), /TOOL_DRIFT|not in the source commit/);
    });

    it("refuses a source commit the checkout does not descend from, or that is not a commit", function () {
      assert.throws(() => manifestFrom(ctx, { ...INPUTS, sourceCommit: "f".repeat(40) }), /SOURCE_COMMIT/);
      assert.throws(() => manifestFrom(ctx, { ...INPUTS, sourceCommit: "debed530" }), /SOURCE_COMMIT/);
    });

    it("plans exactly one proof under the complete egress boundary and names the files the run will produce", function () {
      expect(m.plan.proofs).to.equal(1);
      expect(m.plan.gate).to.equal("sp1:prove:archive-only");
      expect(m.plan.measurement).to.equal(ATTRIBUTED_RUN_SCRIPT_REL);
      expect(m.plan.observer).to.deep.equal({
        script: OBSERVER_SCRIPT_REL,
        mode: "run",
        boundary: "COMPLETE_EGRESS_BOUNDARY",
      });
      expect(m.plan.outputs.runObservation).to.equal(
        `evidence/zk/sp1-impl/observations/proof-exercise-run-${INPUTS.hostLabel}.<token>.raw.json`,
      );
      expect(m.plan.outputs.verificationObservation).to.equal(
        `evidence/zk/sp1-impl/observations/proof-exercise-verification-${INPUTS.hostLabel}.<token>.raw.json`,
      );
      expect(m.plan.outputs.record).to.equal(
        `evidence/zk/sp1-impl/proof-exercises/${ctx.anchor.designation}.v2.<token>.json`,
      );
      expect(m.plan.outputs.token).to.include("first 16");
    });

    it("classifies every artifact the proof needs and passes the acquisition gate without acquiring anything", function () {
      expect(m.artifacts.length).to.be.at.least(12);
      for (const a of m.artifacts) {
        expect(ACQUISITION_PASSING_CLASSES).to.include(a.class);
        expect(a.acquisition).to.equal("NONE");
        expect(a.name.length).to.be.greaterThan(0);
        expect(a.verifiedBy.length).to.be.greaterThan(0);
      }
      const names = m.artifacts.map((a) => a.name).join("\n");
      expect(names).to.match(/guest ELF/);
      expect(names).to.match(/host binary/);
      expect(names).to.match(/circuit/);
      expect(names).to.match(/gnark/);
      expect(names).to.match(/kernel/);
      expect(names).to.match(/[Dd]ocker/);
      expect(m.artifacts.filter((a) => a.class === "host-dependent").length).to.be.at.least(3);
      expect(m.acquisitionGate).to.deep.equal({ verdict: "PASSED", blockers: [] });
    });

    it("lists what it was derived from, each with the digest of its committed bytes", function () {
      const paths = m.derivedFrom.map((d) => d.path);
      for (const p of [
        `evidence/zk/sp1/designations/${ctx.anchor.designation}.json`,
        m.circuit.archiveRecord.path,
        QUALIFICATION_REL,
        EXPECTED_PUBLIC_VALUES_SOURCE_REL,
        TOOLCHAIN_ENV_REL,
        HOST_LOCKFILE_REL,
        GUEST_MANIFEST_REL,
        "zkvm/fixtures/mldsa65-withdrawal.inputs.json",
      ]) {
        expect(paths).to.include(p);
      }
      expect(paths).to.deep.equal([...paths].sort());
      for (const d of m.derivedFrom) expect(d.sha256).to.equal(sha256(lf(readFileSync(d.path, "utf8"))));
    });
  });

  describe("the validator", function () {
    const m = manifestFrom(ctx, INPUTS);
    const text = serializeManifest(m);

    it("accepts what it derives, as JSON text ending in one newline", function () {
      expect(text.endsWith("}\n")).to.equal(true);
      expect(text).to.not.include("\r");
      expect(manifestErrors(JSON.parse(text), ctx)).to.deep.equal([]);
    });

    it("refuses what is not a manifest", function () {
      expect(manifestErrors(null, ctx)).to.not.deep.equal([]);
      expect(manifestErrors([], ctx)).to.not.deep.equal([]);
      expect(manifestErrors({ ...m, schema: "walletwall.other.v1" }, ctx).join("\n")).to.include("SCHEMA");
      expect(manifestErrors({ ...m, lane: "SP1-PA3C" }, ctx).join("\n")).to.include("LANE");
      expect(manifestErrors({ ...m, productionSp1Binding: "ESTABLISHED" }, ctx).join("\n")).to.include(
        "PRODUCTION_SP1_BINDING",
      );
    });

    it("refuses a manifest whose operator inputs are malformed", function () {
      const bad = clone(m);
      (bad.authorization as { proofs: number }).proofs = 2;
      expect(manifestErrors(bad, ctx).join("\n")).to.include("AUTHORIZATION");
      const noWords = clone(m);
      noWords.authorization.words = "";
      expect(manifestErrors(noWords, ctx).join("\n")).to.include("AUTHORIZATION");
      const late = clone(m);
      late.startedAtUtc = "yesterday";
      expect(manifestErrors(late, ctx).join("\n")).to.include("STARTED_AT");
      const host = clone(m);
      host.environment.hostLabel = "Not A Label";
      expect(manifestErrors(host, ctx).join("\n")).to.include("HOST_LABEL");
    });

    it("refuses every derived leaf that differs from what the checkout derives, naming the leaf", function () {
      const vkey = clone(m);
      vkey.statement.programVKey = `0x${"11".repeat(32)}`;
      expect(manifestErrors(vkey, ctx).join("\n")).to.include("statement.programVKey");
      const member = clone(m);
      member.circuit.members[0].sha256 = "00".repeat(32);
      expect(manifestErrors(member, ctx).join("\n")).to.include("circuit.members");
      const pv = clone(m);
      pv.statement.expectedPublicValues.sha256 = "00".repeat(32);
      expect(manifestErrors(pv, ctx).join("\n")).to.include("statement.expectedPublicValues.sha256");
      const gate = clone(m);
      gate.acquisitionGate.verdict = "BLOCKED";
      expect(manifestErrors(gate, ctx).join("\n")).to.include("acquisitionGate");
      const extra = { ...clone(m), note: "added" };
      expect(manifestErrors(extra, ctx).join("\n")).to.include("note");
      const fewer = clone(m) as Partial<Manifest>;
      delete fewer.artifacts;
      expect(manifestErrors(fewer, ctx).join("\n")).to.include("artifacts");
    });

    it("refuses a manifest whose source commit no longer holds the checkout's tools (drift after authoring)", function () {
      const drifted = withFiles(ctx, {}, { [ATTRIBUTED_RUN_SCRIPT_REL]: "// changed since\n" });
      expect(manifestErrors(JSON.parse(text), drifted).join("\n")).to.include("TOOL_DRIFT");
    });

    it("refuses a manifest whose observer qualification has changed under it", function () {
      const q = JSON.parse(readFileSync(QUALIFICATION_REL, "utf8"));
      const changed = withFiles(ctx, {
        [QUALIFICATION_REL]: JSON.stringify({ ...q, qualifiedAtUtc: "2026-01-01T00:00:00Z" }),
      });
      expect(manifestErrors(JSON.parse(text), changed).join("\n")).to.include("environment.qualification");
      const blocked = withFiles(ctx, {
        [QUALIFICATION_REL]: JSON.stringify({
          ...q,
          state: "OBSERVER_QUALIFICATION_BLOCKED",
          blockers: ["x"],
          next: null,
        }),
      });
      expect(manifestErrors(JSON.parse(text), blocked).join("\n")).to.include("OBSERVER_NOT_QUALIFIED");
    });
  });

  describe("the committed manifest", function () {
    it("is what the checkout derives from its own operator inputs, byte for byte, and passes the gate", function () {
      const committedText = lf(readFileSync(MANIFEST_REL, "utf8"));
      const committed = JSON.parse(committedText) as Manifest;
      expect(manifestErrors(committed, ctx)).to.deep.equal([]);
      const inputs = manifestInputsOf(committed);
      expect(inputs).to.not.equal(null);
      expect(serializeManifest(manifestFrom(ctx, inputs as ManifestInputs))).to.equal(committedText);
      expect(committed.acquisitionGate.verdict).to.equal("PASSED");
      expect(committed.authorization.proofs).to.equal(1);
      expect(committed.source.commit).to.not.equal(ctx.headCommit);
    });

    it("names the owner's merge of the qualification lane as its source: a merge commit with two parents", function () {
      const committed = JSON.parse(lf(readFileSync(MANIFEST_REL, "utf8"))) as Manifest;
      expect(committed.source.parents).to.have.length(2);
      expect(committed.source.commit).to.not.equal("5ac076fed62d9dde49e8a871d8370bb1ea0c03d7");
      expect(committed.source.parents).to.include("e8a5c85ce5aaf151aeb5aa62418890ed1195d86e");
    });

    it("has the shape its JSON schema names", function () {
      const committed = JSON.parse(lf(readFileSync(MANIFEST_REL, "utf8")));
      const schema = JSON.parse(lf(readFileSync(MANIFEST_JSON_SCHEMA_REL, "utf8"))) as {
        $id: string;
        required: string[];
        properties: Record<string, unknown>;
        additionalProperties: boolean;
      };
      expect(schema.$id).to.equal(MANIFEST_SCHEMA);
      expect(schema.additionalProperties).to.equal(false);
      expect(Object.keys(committed).sort()).to.deep.equal([...schema.required].sort());
      expect(Object.keys(schema.properties).sort()).to.deep.equal([...schema.required].sort());
    });
  });
});
