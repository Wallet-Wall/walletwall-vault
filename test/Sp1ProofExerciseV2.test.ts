/**
 * SP1-PA3C: the versioned evidence contract (walletwall.sp1-proof-exercise-run.v2 and the v2 record) beside SP1-PA3B's
 * historical v1 evidence. The merged PA3B run, verification and record still validate exactly as before; they are
 * classified EDGE_PROBES_ONLY and never acquire continuous attribution; a v1 validator never accepts a v2 run and a v2
 * validator never accepts a v1 one; a consistent synthetic v2 exercise derives a v2 record and, alone in a temporary
 * repository, the third state, with its assurance carried in the record. No proof is made here. Research prototype.
 * Not audited.
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { serializeJson, productionRecordRel, type ArchiveEvidence } from "../scripts/lib/sp1-circuit-acquisition";
import { CANONICAL_REBUILD_OBSERVATION_REL } from "../scripts/lib/sp1-canonical-build";
import {
  committedProductionAnchor,
  productionArchiveEvidenceOf,
  toolingState,
} from "../scripts/lib/sp1-circuit-tooling";
import { DESIGNATIONS_DIR } from "../scripts/lib/sp1-designation";
import {
  EDGE_PROBES_ONLY,
  normalizeObserverRaw,
  normalizedSha256Of,
  type ObserverEvidence,
} from "../scripts/lib/sp1-egress-attribution";
import {
  ATTRIBUTED_DOES_NOT_ESTABLISH,
  ATTRIBUTED_ESTABLISHES,
  ATTRIBUTED_EXERCISE_LANE,
  ATTRIBUTED_RUN_SCRIPT_REL,
  EGRESS_V2_FIELDS,
  EXERCISE_LANE,
  EXERCISE_RECORD_SCHEMA,
  EXERCISE_RECORD_SCHEMA_V2,
  OBSERVATIONS_DIR,
  OBSERVATION_FIELDS,
  PROOF_INPUT_FIXTURE_REL,
  RUN_SCHEMA,
  RUN_SCHEMA_V2,
  RUN_SCRIPT_REL,
  VERIFICATION_SCRIPT_REL,
  attributedRunObservationErrors,
  commitContentErrors,
  deriveExerciseRecord,
  egressAssuranceOfRecord,
  exerciseErrors,
  exerciseEvidenceState,
  exerciseExpectations,
  exerciseRecordRel,
  isAttributedRun,
  productionExerciseEvidence,
  runObservationErrors,
  type AttributedProofExerciseRecord,
  type AttributedRunObservation,
  type ExerciseExpectations,
  type ProofExerciseRecord,
  type RunObservation,
} from "../scripts/lib/sp1-proof-exercise";
import { OBSERVER_SCRIPT_REL } from "../scripts/sp1-egress-observer";
import { tempDirs } from "./helpers/circuit-tooling";
import {
  ANCHOR,
  ARCHIVE_RECORD,
  ARCHIVE_RECORD_TEXT,
  EXPECTATIONS,
  HOST_BINARY_SHA,
  runObservation,
  runSha,
  verificationObservation,
} from "./helpers/sp1ProofExercise";
import { BOOT_ID, HOST_EXE, OBSERVER_SHA, standardRaw, type RunHooks } from "./helpers/sp1EgressTrace";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const ATTRIBUTED_SHA = "66".repeat(32);
const X2: ExerciseExpectations = {
  ...EXPECTATIONS,
  scripts: { ...EXPECTATIONS.scripts, attributedRun: ATTRIBUTED_SHA, observer: OBSERVER_SHA },
};
const PA3B_RUN = "evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.raw.json";
const PA3B_RECORD = "evidence/zk/sp1-impl/proof-exercises/mldsa65-withdrawal-d1.json";

/** A consistent v2 run: the synthetic v1 run, the attributed tool, and an observer section of the standard capture. */
function attributedRun(hooks: RunHooks = {}, observerSha = OBSERVER_SHA): AttributedRunObservation {
  const run = runObservation();
  const observer = normalizeObserverRaw(standardRaw(hooks, { observerSha }), HOST_EXE);
  return {
    ...run,
    schema: RUN_SCHEMA_V2,
    tool: { script: ATTRIBUTED_RUN_SCRIPT_REL, scriptSha256: ATTRIBUTED_SHA },
    egress: { ...run.egress, observer },
    platform: [...run.platform, `bootId=${BOOT_ID}`],
  };
}
const v2Reasons = (mutate: (r: AttributedRunObservation) => void, x: ExerciseExpectations = X2) => {
  const r = attributedRun();
  mutate(r);
  return attributedRunObservationErrors(r, x).map((e) => e.reason);
};
function resealed(o: ObserverEvidence, edit: (x: ObserverEvidence) => void): ObserverEvidence {
  const c = structuredClone(o);
  edit(c);
  const { normalizedSha256: _d, ...body } = c;
  return { ...c, normalizedSha256: normalizedSha256Of(body) };
}

describe("SP1-PA3C — the v2 evidence contract beside SP1-PA3B's v1 evidence", function () {
  describe("SP1-PA3B's merged evidence, unchanged", function () {
    const anchor = committedProductionAnchor(".");
    const archive = productionArchiveEvidenceOf(".");
    const expectReal = () => exerciseExpectations(".", { anchor, archive });
    const run = JSON.parse(readFileSync(PA3B_RUN, "utf8")) as RunObservation;
    const record = JSON.parse(readFileSync(PA3B_RECORD, "utf8")) as ProofExerciseRecord;

    it("still validates as v1, and the judge still derives exactly the committed record (SELF_HOSTED_PATH_EXERCISED)", function () {
      this.timeout(120_000);
      expect(run.schema).to.equal(RUN_SCHEMA);
      expect(runObservationErrors(run, expectReal())).to.deep.equal([]);
      const e = productionExerciseEvidence(".", { anchor, archive });
      expect(exerciseEvidenceState(e), e.errors.join("; ")).to.equal("ACCEPTED");
      expect(serializeJson(e.record)).to.equal(readFileSync(PA3B_RECORD, "utf8").replace(/\r\n/g, "\n"));
      expect(toolingState({ selfTestPassed: true, archive, exercise: e })).to.equal("SELF_HOSTED_PATH_EXERCISED");
    });

    it("is edge-probed only: no observer, no v2 reading, and the unattributed refusals stay unknown (null, never 0)", function () {
      expect(isAttributedRun(run)).to.equal(false);
      expect(Object.keys(run.egress).sort()).to.deep.equal(["after", "before", "condition", "enforcement"]);
      expect(attributedRunObservationErrors(run, expectReal()).map((r) => r.reason)).to.include.members([
        "OBSERVATION_SCHEMA",
        "OBSERVATION_SHAPE",
        "TOOL_NOT_BOUND",
      ]);
      const a = egressAssuranceOfRecord(record);
      expect(a).to.deep.equal(EDGE_PROBES_ONLY);
      expect([a.continuousObservation, a.processAttribution, a.unattributedEvents, a.events]).to.deep.equal([
        "ABSENT",
        "ABSENT",
        null,
        null,
      ]);
      expect(record.schema).to.equal(EXERCISE_RECORD_SCHEMA);
      expect(record.lane).to.equal(EXERCISE_LANE);
      expect(Object.keys(record.egress).sort()).to.deep.equal(["condition", "enforcement", "probes"]);
      expect(record.doesNotEstablish).to.include("nor that egress stayed refused between the two probes");
    });

    it("binds the frozen tools: the v1 measurement and verification tools at PA3B's source commit, as committed now", function () {
      const x = expectReal();
      expect(x.scripts.run).to.equal(run.tool.scriptSha256);
      expect(commitContentErrors(".", run.source.commit, x)).to.deep.equal([]);
      // The v2 rule asks the PA3B commit for the attributed tool and the observer, which it predates.
      expect(commitContentErrors(".", run.source.commit, x, RUN_SCHEMA_V2).join("\n")).to.match(
        /does not hold scripts\/measure-sp1-attributed-proof-exercise\.ts/,
      );
      expect(x.scripts.attributedRun).to.match(/^[0-9a-f]{64}$/);
      expect(x.scripts.observer).to.match(/^[0-9a-f]{64}$/);
    });
  });

  describe("a v2 run observation", function () {
    it("is accepted when every v1 rule, the attributed tool and the observer's evidence agree", function () {
      expect(attributedRunObservationErrors(attributedRun(), X2)).to.deep.equal([]);
      expect(isAttributedRun(attributedRun())).to.equal(true);
    });

    it("is never accepted by the v1 validator, and a v1 run is never accepted by the v2 validator", function () {
      expect(runObservationErrors(attributedRun(), X2).map((r) => r.reason)).to.include.members([
        "OBSERVATION_SCHEMA",
        "OBSERVATION_SHAPE",
      ]);
      expect(attributedRunObservationErrors(runObservation(), X2).map((r) => r.reason)).to.include(
        "OBSERVATION_SCHEMA",
      );
      expect(v2Reasons((r) => (r.schema = RUN_SCHEMA))).to.include("OBSERVATION_SCHEMA");
    });

    it("binds the attributed tool as committed, never the v1 tool", function () {
      expect(v2Reasons((r) => (r.tool.scriptSha256 = "00".repeat(32)))).to.include("TOOL_NOT_BOUND");
      // The attributed tool's digest under the v1 tool's path is not the attributed tool either.
      expect(v2Reasons((r) => (r.tool.script = RUN_SCRIPT_REL))).to.include("TOOL_NOT_BOUND");
      expect(
        v2Reasons((r) => (r.tool = { script: RUN_SCRIPT_REL, scriptSha256: String(EXPECTATIONS.scripts.run) })),
      ).to.include("TOOL_NOT_BOUND");
      expect(v2Reasons(() => undefined, { ...X2, scripts: { ...X2.scripts, attributedRun: null } })).to.include(
        "TOOL_NOT_BOUND",
      );
      expect(
        v2Reasons(() => undefined, { ...X2, scripts: { run: X2.scripts.run, verification: X2.scripts.verification } }),
      ).to.include.members(["TOOL_NOT_BOUND"]);
    });

    it("keeps every v1 rule on the shared fields (the same validator, never a weaker copy)", function () {
      expect(v2Reasons((r) => (r.proof.vkey = `0x${"ee".repeat(32)}`))).to.include("PROOF_MISMATCH");
      expect(v2Reasons((r) => (r.prover.mode = "network" as "cpu"))).to.include("PROVER_MODE_MISMATCH");
      expect(v2Reasons((r) => (r.egress.condition = "EGRESS_NOT_REFUSED"))).to.include("EGRESS_NOT_DISABLED");
      expect(v2Reasons((r) => (r.hostExecutable.sha256 = "00".repeat(32)))).to.include("HOST_IDENTITY_MISMATCH");
      expect(v2Reasons((r) => (r.source.zkvmHostTree = "b".repeat(40)))).to.include("HOST_IDENTITY_MISMATCH");
      expect(v2Reasons((r) => ((r as unknown as Record<string, unknown>).extra = 1))).to.include("OBSERVATION_SHAPE");
      expect(v2Reasons((r) => ((r.egress as unknown as Record<string, unknown>).observed = true))).to.include(
        "OBSERVATION_SHAPE",
      );
      expect(v2Reasons((r) => delete (r.egress as Partial<AttributedRunObservation["egress"]>).observer)).to.include(
        "OBSERVATION_SHAPE",
      );
    });

    it("carries the observer's refusals, and binds the observer to this run's host, boot, executable and commit", function () {
      expect(v2Reasons((r) => (r.egress.observer.normalizedSha256 = "00".repeat(32)))).to.include(
        "NORMALIZED_NOT_BOUND",
      );
      expect(v2Reasons(() => undefined, { ...X2, scripts: { ...X2.scripts, observer: "00".repeat(32) } })).to.include(
        "TOOL_NOT_BOUND",
      );
      expect(v2Reasons((r) => (r.platform = r.platform.filter((l) => !l.startsWith("bootId="))))).to.include(
        "OBSERVER_NOT_THIS_RUN",
      );
      expect(
        v2Reasons(
          (r) =>
            (r.egress.observer = resealed(
              r.egress.observer,
              (o) => (o.hostExecutable.path = "/srv/sp1/bin/other-host"),
            )),
        ),
      ).to.include("HOST_IDENTITY_MISMATCH");
      // The measured file and the file the observer followed are one file: the tie on its own.
      expect(v2Reasons((r) => (r.hostExecutable.file = "mldsa65-host-other"))).to.deep.equal([
        "HOST_IDENTITY_MISMATCH",
      ]);
      expect(v2Reasons((r) => (r.source.commit = "d".repeat(40)))).to.include("OBSERVER_NOT_THIS_RUN");
      expect(v2Reasons((r) => (r.host = "proving-host-b"))).to.include("OBSERVER_NOT_THIS_RUN");
      expect(v2Reasons((r) => (r.timing.startedAtUtc = "2026-11-01T09:30:00Z"))).to.include("OBSERVER_CLOCK");
      expect(v2Reasons((r) => (r.egress.after = r.egress.after.slice(1)))).to.include("EGRESS_NOT_DISABLED");
    });
  });

  describe("the record a v2 run derives", function () {
    const binding = (r: unknown) => ({
      runSha256: runSha(r as RunObservation),
      verificationPath: `${OBSERVATIONS_DIR}/proof-exercise-verification-proving-host-a.raw.json`,
      runPath: `${OBSERVATIONS_DIR}/proof-exercise-run-proving-host-a.raw.json`,
    });

    it("is a v2 record: the v1 record's facts, the attributed lane, and the assurance derived from the evidence", function () {
      const run = attributedRun({});
      const v = verificationObservation(run as unknown as RunObservation);
      expect(exerciseErrors(run, v, binding(run), X2)).to.deep.equal([]);
      const rec = deriveExerciseRecord(run, v, binding(run), X2) as AttributedProofExerciseRecord;
      const v1 = deriveExerciseRecord(
        runObservation(),
        verificationObservation(),
        binding(runObservation()),
        EXPECTATIONS,
      );
      expect([rec.schema, rec.lane, rec.establishes, rec.doesNotEstablish]).to.deep.equal([
        EXERCISE_RECORD_SCHEMA_V2,
        ATTRIBUTED_EXERCISE_LANE,
        ATTRIBUTED_ESTABLISHES,
        ATTRIBUTED_DOES_NOT_ESTABLISH,
      ]);
      expect(rec.egress.assurance).to.deep.include({
        level: "CONTINUOUS_ATTRIBUTED",
        continuousObservation: "PRESENT",
        processAttribution: "COMPLETE",
        unattributedEvents: 0,
      });
      expect(egressAssuranceOfRecord(rec)).to.deep.equal(rec.egress.assurance);
      const {
        egress: e2,
        schema: _s,
        lane: _l,
        establishes: _e,
        doesNotEstablish: _d,
        exercise: _x,
        derivedFrom: _f,
        ...shared2
      } = rec;
      const {
        egress: e1,
        schema: _s1,
        lane: _l1,
        establishes: _e1,
        doesNotEstablish: _d1,
        exercise: _x1,
        derivedFrom: _f1,
        ...shared1
      } = v1;
      expect(shared2).to.deep.equal(shared1);
      const { assurance: _a, ...edges } = e2;
      expect(edges).to.deep.equal(e1);
    });

    it("keeps the v1 derivation exactly as it was: the same record, no assurance key, the PA3B lane", function () {
      const v1 = deriveExerciseRecord(
        runObservation(),
        verificationObservation(),
        binding(runObservation()),
        EXPECTATIONS,
      );
      expect([v1.schema, v1.lane]).to.deep.equal([EXERCISE_RECORD_SCHEMA, EXERCISE_LANE]);
      expect(Object.keys(v1.egress).sort()).to.deep.equal(["condition", "enforcement", "probes"]);
      expect(egressAssuranceOfRecord(v1)).to.deep.equal(EDGE_PROBES_ONLY);
    });

    it("derives nothing from a v2 run the observer's evidence refuses, and no assurance from a record that claims one it lacks", function () {
      const run = attributedRun({ duringProof: (b) => b.marker("FAIL", { code: "OBSERVER_LOSS" }) });
      const v = verificationObservation(run as unknown as RunObservation);
      expect(() => deriveExerciseRecord(run, v, binding(run), X2)).to.throw(/OBSERVER_FAILED/);
      const forged = {
        ...deriveExerciseRecord(runObservation(), verificationObservation(), binding(runObservation()), EXPECTATIONS),
        schema: EXERCISE_RECORD_SCHEMA_V2,
      };
      expect(() => egressAssuranceOfRecord(forged)).to.throw(/carries no egress assurance/);
      expect(() => egressAssuranceOfRecord({ ...forged, schema: "walletwall.sp1-proof-exercise.v0" })).to.throw();
      // An assurance under a schema that is neither v1 nor v2 is read as nothing.
      const ok = attributedRun();
      const v2 = deriveExerciseRecord(ok, verificationObservation(ok as unknown as RunObservation), binding(ok), X2);
      expect(() => egressAssuranceOfRecord({ ...v2, schema: "walletwall.sp1-proof-exercise.v3" })).to.throw(
        /carries no egress assurance/,
      );
    });
  });

  describe("a v2 exercise alone in a temporary repository", function () {
    const dirs = tempDirs();
    afterEach(() => dirs.cleanup());
    const git = (cwd: string, ...args: string[]) => {
      const r = spawnSync("git", ["-c", "core.autocrlf=false", ...args], { cwd, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout.trim();
    };
    const write = (d: string, rel: string, text: string) => {
      mkdirSync(join(d, dirname(rel)), { recursive: true });
      writeFileSync(join(d, rel), text);
    };
    const commit = (d: string, m: string) => {
      git(d, "add", "-A");
      git(d, "commit", "-q", "--allow-empty", "-m", m);
      return git(d, "rev-parse", "HEAD");
    };
    const archive: ArchiveEvidence = {
      records: [productionRecordRel(ANCHOR)],
      record: ARCHIVE_RECORD,
      observations: [],
      errors: [],
    };
    const RUN_FILE = `${OBSERVATIONS_DIR}/proof-exercise-run-proving-host-a.raw.json`;
    const VERIFICATION_FILE = `${OBSERVATIONS_DIR}/proof-exercise-verification-proving-host-a.raw.json`;

    /**
     * The archived state with the attributed tool and the observer committed, then one attributed exercise; with
     * `olderObserverAtSource`, the run names the first commit, which held another observer than the one now committed.
     */
    function repo(edit?: (run: AttributedRunObservation) => void, opts: { olderObserverAtSource?: boolean } = {}) {
      const d = dirs.make("sp1-pa3c-");
      git(d, "init", "-q");
      git(d, "config", "user.email", "test@example.invalid");
      git(d, "config", "user.name", "test");
      git(d, "config", "commit.gpgsign", "false");
      write(d, productionRecordRel(ANCHOR), ARCHIVE_RECORD_TEXT);
      write(d, "zkvm/host/src/main.rs", "fn main() {}\n");
      write(d, PROOF_INPUT_FIXTURE_REL, '{\n  "synthetic": "proof input fixture"\n}\n');
      write(d, RUN_SCRIPT_REL, "// synthetic v1 measurement tool\n");
      write(d, VERIFICATION_SCRIPT_REL, "// synthetic verification tool\n");
      write(d, ATTRIBUTED_RUN_SCRIPT_REL, "// synthetic attributed measurement tool\n");
      write(d, OBSERVER_SCRIPT_REL, opts.olderObserverAtSource ? "// an older observer\n" : "// synthetic observer\n");
      for (const host of ["developer-workstation", "github-hosted-runner"]) {
        write(
          d,
          `${OBSERVATIONS_DIR}/circuit-acquisition-${host}.raw.json`,
          serializeJson({ host, transfer: { remoteIp: "203.0.113.5" } }),
        );
      }
      const first = commit(d, "the tools");
      if (opts.olderObserverAtSource) write(d, OBSERVER_SCRIPT_REL, "// synthetic observer\n");
      const tree = git(d, "rev-parse", "HEAD:zkvm/host");
      write(
        d,
        `${DESIGNATIONS_DIR}/${ANCHOR.designation}.json`,
        serializeJson({ id: ANCHOR.designation, sequence: 1, subject: { zkvmHostTree: tree } }),
      );
      write(
        d,
        CANONICAL_REBUILD_OBSERVATION_REL,
        serializeJson({
          builds: [{ hostId: "x", subject: { zkvmHostTree: tree }, hostBinarySha256: HOST_BINARY_SHA }],
        }),
      );
      const base = commit(d, "archived state");
      const source = opts.olderObserverAtSource ? first : base;
      const x = exerciseExpectations(d, { anchor: ANCHOR, archive });
      const run = attributedRun({ commit: source }, String(x.scripts.observer));
      run.source.commit = source;
      run.source.zkvmHostTree = x.zkvmHostTree;
      run.inputs.sha256 = String(x.proofInputSha256);
      run.tool.scriptSha256 = String(x.scripts.attributedRun);
      const v = verificationObservation(run as unknown as RunObservation);
      v.run = { path: RUN_FILE, sha256: runSha(run as unknown as RunObservation) };
      v.tool.scriptSha256 = String(x.scripts.verification);
      const rec = deriveExerciseRecord(
        run,
        v,
        { runSha256: runSha(run as unknown as RunObservation), verificationPath: VERIFICATION_FILE, runPath: RUN_FILE },
        x,
      );
      const written = structuredClone(run);
      edit?.(written);
      write(d, RUN_FILE, serializeJson(written));
      write(d, VERIFICATION_FILE, serializeJson(v));
      write(d, exerciseRecordRel(ANCHOR), serializeJson(rec));
      commit(d, "the attributed exercise");
      return { d, rec, x };
    }

    it("is ACCEPTED: the judge derives the committed v2 record and the third state, with its assurance in the record", function () {
      this.timeout(120_000);
      const { d, rec } = repo();
      const e = productionExerciseEvidence(d, { anchor: ANCHOR, archive });
      expect(exerciseEvidenceState(e), e.errors.join("; ")).to.equal("ACCEPTED");
      expect(e.record).to.deep.equal(rec);
      expect(egressAssuranceOfRecord(e.record as ProofExerciseRecord).level).to.equal("CONTINUOUS_ATTRIBUTED");
      expect(toolingState({ selfTestPassed: true, archive, exercise: e })).to.equal("SELF_HOSTED_PATH_EXERCISED");
    });

    it("is REFUSED when the observation was edited after the record was derived, or ran at a commit without the tools", function () {
      this.timeout(120_000);
      const edited = repo((r) => (r.egress.observer.events = r.egress.observer.events.slice(0, -1)));
      const e = productionExerciseEvidence(edited.d, { anchor: ANCHOR, archive });
      expect(exerciseEvidenceState(e)).to.equal("REFUSED");
      expect(e.errors.join("\n")).to.match(/NORMALIZED_NOT_BOUND|RUN_NOT_BOUND|not the record/);
      const { d, x } = repo();
      const first = git(d, "rev-list", "--max-parents=0", "HEAD");
      expect(commitContentErrors(d, first, x, RUN_SCHEMA_V2)).to.deep.equal([]);
      writeFileSync(join(d, OBSERVER_SCRIPT_REL), "// another observer\n");
      const later = exerciseExpectations(d, { anchor: ANCHOR, archive });
      expect(commitContentErrors(d, first, later, RUN_SCHEMA_V2).join("\n")).to.match(
        /does not hold scripts\/sp1-egress-observer\.ts as committed/,
      );
      expect(commitContentErrors(d, first, later)).to.deep.equal([]);
    });

    it("is REFUSED by the judge when the run's commit held another observer than the one it names", function () {
      this.timeout(120_000);
      const { d } = repo(undefined, { olderObserverAtSource: true });
      const e = productionExerciseEvidence(d, { anchor: ANCHOR, archive });
      expect(exerciseEvidenceState(e)).to.equal("REFUSED");
      expect(e.errors.join("\n")).to.match(/does not hold scripts\/sp1-egress-observer\.ts as committed/);
    });
  });

  describe("the commands (nothing is observed, proved or written)", function () {
    const run = (script: string, args: string[], input?: string) =>
      spawnSync(process.execPath, [join("node_modules", "tsx", "dist", "cli.mjs"), script, ...args], {
        cwd: ".",
        encoding: "utf8",
        env: { ...process.env, FORCE_COLOR: "0" },
        input: input ?? "",
        timeout: 120_000,
      });

    it("sp1:proof-exercise-record --validate names SP1-PA3B's assurance: edge probes only, nothing observed between them", function () {
      this.timeout(120_000);
      const r = run("scripts/generate-sp1-proof-exercise-record.ts", ["--validate"]);
      expect(r.status, r.stderr).to.equal(0);
      expect(r.stdout).to.include("SELF_HOSTED_PATH_EXERCISED");
      expect(r.stdout).to.include(
        "egress assurance EDGE_PROBES_ONLY (continuous observation ABSENT, process attribution ABSENT)",
      );
    });

    it("the attributed measurement refuses before any act: its arguments, then a host that is not Linux, then an absent observer", function () {
      this.timeout(120_000);
      const before = readFileSync(PA3B_RUN);
      const none = run(ATTRIBUTED_RUN_SCRIPT_REL, []);
      expect(none.status).to.equal(1);
      expect(`${none.stdout}\n${none.stderr}`).to.include("--record is required");
      const args = (host: string) => [
        "--record",
        "absent-record.json",
        "--circuit-root",
        "/srv/absent",
        "--host",
        host,
        "--inputs",
        "/srv/absent/inputs.json",
        "--host-label",
        "proving-host-a",
        "--enforcement",
        "synthetic",
        "--out",
        "absent-out.json",
      ];
      const relative = run(ATTRIBUTED_RUN_SCRIPT_REL, args("mldsa65-host"));
      expect(`${relative.stdout}\n${relative.stderr}`).to.include("--host must be absolute");
      const full = run(ATTRIBUTED_RUN_SCRIPT_REL, args("/srv/absent/mldsa65-host"));
      expect(full.status).to.equal(1);
      expect(`${full.stdout}\n${full.stderr}`).to.match(
        /PROVE_HOST_UNSUPPORTED \(NOT_LINUX\)|the observer is gone|not started by the egress observer/,
      );
      expect(readFileSync(PA3B_RUN).equals(before)).to.equal(true);
    });
  });

  describe("the JSON schemas name what the validators judge", function () {
    const run2 = JSON.parse(readFileSync("evidence/zk/schema/sp1-proof-exercise-run.v2.schema.json", "utf8"));
    const rec2 = JSON.parse(readFileSync("evidence/zk/schema/sp1-proof-exercise.v2.schema.json", "utf8"));

    it("the run observation v2 schema: the same top-level fields as v1, egress with the observer", function () {
      expect(run2.$id).to.equal(RUN_SCHEMA_V2);
      expect(run2.properties.schema.const).to.equal(RUN_SCHEMA_V2);
      expect([...run2.required].sort()).to.deep.equal([...OBSERVATION_FIELDS.run].sort());
      expect([...run2.properties.egress.required].sort()).to.deep.equal([...EGRESS_V2_FIELDS].sort());
      expect(run2.properties.tool.properties.script.const).to.equal(ATTRIBUTED_RUN_SCRIPT_REL);
    });

    it("the record v2 schema: the v1 record's fields, the attributed lane, egress with its assurance", function () {
      const v1 = JSON.parse(readFileSync("evidence/zk/schema/sp1-proof-exercise.v1.schema.json", "utf8"));
      expect(rec2.$id).to.equal(EXERCISE_RECORD_SCHEMA_V2);
      expect([...rec2.required].sort()).to.deep.equal([...v1.required].sort());
      expect(rec2.properties.lane.const).to.equal(ATTRIBUTED_EXERCISE_LANE);
      expect(rec2.properties.egress.required).to.include("assurance");
      expect(rec2.properties.egress.properties.assurance.properties.level.enum).to.deep.equal([
        "CONTINUOUS_ATTRIBUTED",
        "CONTINUOUS_PARTIALLY_ATTRIBUTED",
      ]);
      expect(sha256(readFileSync("evidence/zk/schema/sp1-proof-exercise.v1.schema.json"))).to.equal(
        "a8863f4ac2a94205db51439e42d05d59cfeb0626515a7a2235936c2ae06eff62",
      );
    });
  });
});
