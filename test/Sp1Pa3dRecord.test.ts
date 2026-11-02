/**
 * SP1-PA3D: the exercise record (scripts/lib/sp1-pa3d-record.ts): the attribution chain from the source commit through
 * the manifest, the pre-proof attestation, the run observation, the proof's digests, the verification observation and
 * the v2 record to the observer qualification the run stood on, each link a comparison of committed digests or of
 * commit ancestry; the attribution residue stated by count, never excused; the reproducibility statement (the
 * statement's public values reproduced, proof-byte determinism not claimed); the state recomputed from facts; and the
 * pure negative controls the validator re-runs. Offline. Research prototype. Not audited.
 */
import { expect } from "chai";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

import { PROOF_INVALID } from "../scripts/lib/sp1-chain-execution";
import type { BoundaryRule } from "../scripts/lib/sp1-egress-attribution";
import { MANIFEST_REL, type Manifest } from "../scripts/lib/sp1-pa3d-exercise";
import { preproofObservationRel, type PreproofObservation } from "../scripts/lib/sp1-pa3d-preproof";
import {
  PA3D_NEGATIVE_CONTROLS,
  RECORD_JSON_SCHEMA_REL,
  RECORD_KEYS,
  RECORD_REL,
  RECORD_SCHEMA,
  boundaryClassOf,
  boundaryOfSnapshots,
  chainOf,
  pa3dInputsFromRepo,
  pa3dRecordErrors,
  pa3dRecordFrom,
  pa3dStateOf,
  reproducibilityOf,
  runPa3dNegativeControls,
  serializePa3dRecord,
  type ExerciseView,
  type Pa3dInputs,
  type Pa3dRecord,
} from "../scripts/lib/sp1-pa3d-record";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

const manifestText = lf(readFileSync(MANIFEST_REL, "utf8"));
const manifest = JSON.parse(manifestText) as Manifest;
const preproofRel = preproofObservationRel(manifest.environment.hostLabel);
const preproofText = lf(readFileSync(preproofRel, "utf8"));
const preproof = JSON.parse(preproofText) as PreproofObservation;
const PA3B_PROOF_SHA = "dfe975da331d53bee1485d55f032566fd43ddc0350904a30f74bcd83f7370eee";
/** The table SP1-PA3D's run stood under, as the observer recorded it (two snapshots of seven rules). */
const RUN_REL =
  "evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.45aa26274d265d3f.raw.json";
const committedBoundary = (): { n: number; rules: BoundaryRule[] }[] =>
  JSON.parse(lf(readFileSync(RUN_REL, "utf8"))).egress.observer.boundary;

/** A consistent exercise of the committed manifest: every digest the chain compares is the manifest's. */
function exerciseOf(): ExerciseView {
  const runText = '{"synthetic":"run"}\n';
  const runSha = sha256(runText);
  const token = runSha.slice(0, 16);
  const host = manifest.environment.hostLabel;
  return {
    token,
    run: {
      path: `evidence/zk/sp1-impl/observations/proof-exercise-run-${host}.${token}.raw.json`,
      sha256: runSha,
      schema: "walletwall.sp1-proof-exercise-run.v2",
      host,
      measuredAtUtc: "2026-11-02T04:30:00Z",
      source: { commit: manifest.source.commit, zkvmHostTree: manifest.statement.zkvmHostTree },
      toolSha256:
        manifest.tools.find((t) => t.path === "scripts/measure-sp1-attributed-proof-exercise.ts")?.sha256 ?? "",
      programVKey: manifest.statement.programVKey,
      hostExecutableSha256: manifest.prover.hostBinary.sha256,
      inputsSha256: manifest.statement.inputs.sha256,
      archiveRecordSha256: manifest.circuit.archiveRecord.sha256,
      installedMembers: manifest.circuit.members.map((m) => ({ ...m })),
      gnarkDigest: manifest.circuit.gnark.digest,
      proverMode: manifest.prover.mode,
      proof: {
        vkey: manifest.statement.programVKey,
        selector: manifest.circuit.verifier.selector,
        publicValues: manifest.statement.expectedPublicValues.hex,
        publicValuesSha256: manifest.statement.expectedPublicValues.sha256,
        proofBytesSha256: "ab".repeat(32),
      },
      egress: { condition: "EGRESS_DISABLED", probesRefused: true, probes: 16 },
      observer: {
        scriptSha256: manifest.environment.qualification.observerScriptSha256,
        mode: "RUN",
        boundary: "COMPLETE_EGRESS_BOUNDARY",
        bootId: preproof.platform.bootId,
      },
      timing: { startedAtUtc: "2026-11-02T04:15:00Z", finishedAtUtc: "2026-11-02T04:26:00Z", gateSeconds: 660 },
    },
    verification: {
      path: `evidence/zk/sp1-impl/observations/proof-exercise-verification-${host}.${token}.raw.json`,
      sha256: "cd".repeat(32),
      runSha256: runSha,
      acceptance: "ACCEPTED",
      checks: [{ real: "success", tampered: `revert ${PROOF_INVALID}` }],
      proof: { publicValuesSha256: manifest.statement.expectedPublicValues.sha256, proofBytesSha256: "ab".repeat(32) },
      verifierVersion: manifest.circuit.verifier.version,
      runtimeCodeKeccak: manifest.circuit.verifier.runtimeCodeKeccak,
    },
    record: {
      path: `evidence/zk/sp1-impl/proof-exercises/${manifest.statement.designation}.v2.${token}.json`,
      sha256: "ef".repeat(32),
      schema: "walletwall.sp1-proof-exercise.v2",
      lane: "SP1-PA3D",
      proof: { publicValuesSha256: manifest.statement.expectedPublicValues.sha256, proofBytesSha256: "ab".repeat(32) },
      assurance: {
        level: "CONTINUOUS_ATTRIBUTED",
        continuousObservation: "PRESENT",
        processAttribution: "COMPLETE",
        enforcement: "STATED_AND_COUNTED",
        edgeProbes: "REFUSED_BEFORE_AND_AFTER_AND_OBSERVED",
        attemptsInWindow: 160,
        refusedPackets: 230,
        unattributedEvents: 0,
        unattributedOutsideWindow: 0,
        unknownOutcomes: 0,
        unseenDestinations: 0,
        otherNamespaceEgress: 0,
      },
      derivedFrom: [
        `evidence/zk/sp1-impl/observations/proof-exercise-run-${host}.${token}.raw.json`,
        `evidence/zk/sp1-impl/observations/proof-exercise-verification-${host}.${token}.raw.json`,
      ],
    },
  };
}

function inputsOf(exercise: ExerciseView | null = exerciseOf()): Pa3dInputs {
  return {
    manifest: { path: MANIFEST_REL, sha256: sha256(manifestText), value: clone(manifest), errors: [] },
    preproof: { path: preproofRel, sha256: sha256(preproofText), value: clone(preproof), errors: [] },
    qualification: {
      path: manifest.environment.qualification.path,
      sha256: manifest.environment.qualification.sha256,
      observerScriptSha256: manifest.environment.qualification.observerScriptSha256,
      state: "OBSERVER_QUALIFIED_FOR_PA3D",
    },
    provenance: {
      laneCheckout: preproof.laneCheckout.commit,
      manifestInLaneCheckout: true,
      runLaneCheckout: "b".repeat(40),
      attestationInRunCheckout: true,
    },
    pa3bProofBytesSha256: PA3B_PROOF_SHA,
    exercise,
    exerciseErrors: [],
  };
}

describe("SP1-PA3D — the exercise record and its attribution chain", function () {
  this.timeout(60_000);

  it("has a JSON schema naming exactly its fields, closed to others", function () {
    const schema = JSON.parse(lf(readFileSync(RECORD_JSON_SCHEMA_REL, "utf8"))) as {
      $id: string;
      required: string[];
      properties: Record<string, unknown>;
      additionalProperties: boolean;
    };
    expect(schema.$id).to.equal(RECORD_SCHEMA);
    expect(schema.additionalProperties).to.equal(false);
    expect([...schema.required].sort()).to.deep.equal([...RECORD_KEYS].sort());
    expect(Object.keys(schema.properties).sort()).to.deep.equal([...RECORD_KEYS].sort());
    expect(Object.keys(pa3dRecordFrom(inputsOf())).sort()).to.deep.equal([...RECORD_KEYS].sort());
  });

  it("names its schema, its path and seventeen negative controls (five verifier, twelve validator), each with a kind and an expected outcome", function () {
    expect(RECORD_SCHEMA).to.equal("walletwall.sp1-pa3d-exercise-record.v1");
    expect(RECORD_REL).to.equal("evidence/zk/sp1-impl/pa3d-exercise-record.json");
    expect(PA3D_NEGATIVE_CONTROLS.length).to.equal(17);
    const ids = PA3D_NEGATIVE_CONTROLS.map((c) => c.id);
    expect(new Set(ids).size).to.equal(ids.length);
    for (const c of PA3D_NEGATIVE_CONTROLS) {
      expect(["VERIFIER", "VALIDATOR"]).to.include(c.kind);
      expect(["REJECTED", "REFUSED"]).to.include(c.expected);
      expect(c.description.length).to.be.greaterThan(10);
    }
    expect(PA3D_NEGATIVE_CONTROLS.filter((c) => c.kind === "VERIFIER").length).to.equal(5);
    expect(PA3D_NEGATIVE_CONTROLS.filter((c) => c.kind === "VALIDATOR").length).to.equal(12);
  });

  describe("the state", function () {
    it("is a function of the gate, the attestation, the proof and the chain, in that order of precedence", function () {
      expect(
        pa3dStateOf({ gate: "BLOCKED", preproof: "PA3D_PREPROOF_ENVIRONMENT_VALID", exercise: true, chainHolds: true }),
      ).to.equal("PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE");
      expect(
        pa3dStateOf({
          gate: "PASSED",
          preproof: "PA3D_PREPROOF_ENVIRONMENT_REFUSED",
          exercise: true,
          chainHolds: true,
        }),
      ).to.equal("PA3D_PREPROOF_ENVIRONMENT_REFUSED");
      expect(
        pa3dStateOf({
          gate: "PASSED",
          preproof: "PA3D_PREPROOF_ENVIRONMENT_VALID",
          exercise: false,
          chainHolds: false,
        }),
      ).to.equal("PA3D_PROVING_FAILED");
      expect(
        pa3dStateOf({ gate: "PASSED", preproof: "PA3D_PREPROOF_ENVIRONMENT_VALID", exercise: true, chainHolds: false }),
      ).to.equal("PA3D_PROOF_GENERATED_VERIFICATION_BLOCKED");
      expect(
        pa3dStateOf({ gate: "PASSED", preproof: "PA3D_PREPROOF_ENVIRONMENT_VALID", exercise: true, chainHolds: true }),
      ).to.equal("PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED");
    });
  });

  describe("the boundary, classified from the rules the observer recorded", function () {
    const rules = () => committedBoundary()[0].rules;
    const withExpr = (edit: (r: BoundaryRule) => boolean, f: (expr: string) => string) =>
      rules().map((r) => (edit(r) ? { ...r, expr: f(r.expr) } : r));

    it("reads SP1-PA3D's committed table as the complete egress boundary, in both snapshots, which agree", function () {
      const b = committedBoundary();
      expect(b).to.have.length(2);
      expect(boundaryClassOf(b[0].rules)).to.equal("COMPLETE_EGRESS_BOUNDARY");
      expect(boundaryClassOf(b[1].rules)).to.equal("COMPLETE_EGRESS_BOUNDARY");
      expect(boundaryOfSnapshots(b)).to.equal("COMPLETE_EGRESS_BOUNDARY");
    });

    it("refuses the inverse of the local-accept rule, a missing forward drop, a missing resolver refusal or TEST-NET", function () {
      expect(
        boundaryClassOf(
          withExpr(
            (r) => r.expr.includes('"fib"'),
            (e) => e.replace('"op":"=="', '"op":"!="'),
          ),
        ),
      ).to.equal("OTHER");
      expect(boundaryClassOf(rules().filter((r) => r.hook !== "forward"))).to.equal("OTHER");
      expect(boundaryClassOf(rules().filter((r) => !r.expr.includes("10.255.255.254")))).to.equal("OTHER");
      expect(boundaryClassOf(rules().filter((r) => !r.expr.includes("tcp reset")))).to.equal("OTHER");
      expect(boundaryClassOf(rules().filter((r) => !r.expr.includes("admin-prohibited")))).to.equal("OTHER");
      expect(
        boundaryClassOf(
          withExpr(
            (r) => r.expr.includes("10.255.255.254"),
            (e) => e.replace("10.255.255.254", "192.0.2.1"),
          ),
        ),
      ).to.equal("OTHER");
      expect(boundaryClassOf([])).to.equal("OTHER");
    });

    it("refuses snapshots that disagree on their rules, and classifies none as nothing", function () {
      const b = committedBoundary();
      const changed = [b[0], { n: 2, rules: b[1].rules.filter((r) => r.hook !== "forward") }];
      expect(boundaryOfSnapshots(changed)).to.equal("OTHER");
      const noForward = [
        b[0],
        { n: 2, rules: b[1].rules.map((r) => ({ ...r, hook: r.hook === "forward" ? "output" : r.hook })) },
      ];
      expect(boundaryOfSnapshots(noForward)).to.equal("OTHER");
      expect(boundaryOfSnapshots([])).to.equal("OTHER");
      // Counter values differ between snapshots by nature; they are not the rules' identity.
      const counted = [
        b[0],
        { n: 2, rules: b[1].rules.map((r) => ({ ...r, counter: r.counter ? { packets: 9, bytes: 9 } : null })) },
      ];
      expect(boundaryOfSnapshots(counted)).to.equal("COMPLETE_EGRESS_BOUNDARY");
    });
  });

  describe("the attribution chain", function () {
    it("holds, link by link, for an exercise whose every digest is the manifest's", function () {
      const chain = chainOf(inputsOf());
      expect(chain.links.length).to.equal(15);
      for (const link of chain.links) expect(link.holds, `${link.id}: ${link.detail}`).to.equal(true);
      expect(chain.holds).to.equal(true);
      expect(chain.blockers).to.deep.equal([]);
      expect(chain.links.map((l) => l.id)).to.deep.equal([
        "SOURCE_TO_MANIFEST",
        "MANIFEST_TO_ATTESTATION",
        "MANIFEST_IN_ATTESTED_CHECKOUT",
        "SOURCE_TO_RUN",
        "ATTESTATION_IN_RUN_CHECKOUT",
        "PROGRAM_TO_RUN",
        "INPUTS_TO_RUN",
        "STATEMENT_TO_PUBLIC_VALUES",
        "CIRCUIT_TO_RUN",
        "PROOF_TO_VERIFICATION",
        "OBSERVATIONS_TO_RECORD",
        "ATTRIBUTION_RESIDUE",
        "QUALIFICATION_TO_OBSERVER",
        "BOUNDARY_TO_RUN",
        "MANIFEST_BEFORE_PROOF",
      ]);
    });

    const broken = (edit: (e: ExerciseView, i: Pa3dInputs) => void): string[] => {
      const i = inputsOf();
      edit(i.exercise as ExerciseView, i);
      const chain = chainOf(i);
      expect(chain.holds).to.equal(false);
      return chain.blockers;
    };

    it("breaks when the run was made from another commit, by another tool, under another schema or on another host", function () {
      expect(broken((e) => (e.run.source.commit = "b".repeat(40))).join("\n")).to.include("SOURCE_TO_RUN");
      expect(broken((e) => (e.run.toolSha256 = "00".repeat(32))).join("\n")).to.include("SOURCE_TO_RUN");
      expect(broken((e) => (e.run.schema = "walletwall.sp1-proof-exercise-run.v1")).join("\n")).to.include(
        "SOURCE_TO_RUN",
      );
      expect(broken((e) => (e.run.host = "another-host")).join("\n")).to.include("SOURCE_TO_RUN");
    });

    it("breaks when the program, the host binary, the prover mode or the inputs are not the statement's", function () {
      expect(broken((e) => (e.run.programVKey = `0x${"11".repeat(32)}`)).join("\n")).to.include("PROGRAM_TO_RUN");
      expect(broken((e) => (e.run.hostExecutableSha256 = "00".repeat(32))).join("\n")).to.include("PROGRAM_TO_RUN");
      expect(broken((e) => (e.run.proverMode = "network")).join("\n")).to.include("PROGRAM_TO_RUN");
      expect(broken((e) => (e.run.inputsSha256 = "00".repeat(32))).join("\n")).to.include("INPUTS_TO_RUN");
    });

    it("breaks when the public values are not the statement's (a stale proof under a modified manifest)", function () {
      expect(
        broken((e, i) => (i.manifest.value.statement.expectedPublicValues.sha256 = "00".repeat(32))).join("\n"),
      ).to.include("STATEMENT_TO_PUBLIC_VALUES");
      expect(broken((e) => (e.run.proof.publicValues = "0x00")).join("\n")).to.include("STATEMENT_TO_PUBLIC_VALUES");
    });

    it("breaks when the circuit, its members, the gnark image or the selector are not the manifest's", function () {
      expect(broken((e) => (e.run.archiveRecordSha256 = "00".repeat(32))).join("\n")).to.include("CIRCUIT_TO_RUN");
      expect(broken((e) => (e.run.installedMembers[0].sha256 = "00".repeat(32))).join("\n")).to.include(
        "CIRCUIT_TO_RUN",
      );
      expect(broken((e) => (e.run.gnarkDigest = "sha256:" + "00".repeat(32))).join("\n")).to.include("CIRCUIT_TO_RUN");
      expect(broken((e) => (e.run.proof.selector = "0x00000000")).join("\n")).to.include("CIRCUIT_TO_RUN");
    });

    it("breaks when the verification does not bind the run's bytes or the proof's digests, or did not accept", function () {
      expect(broken((e) => (e.verification.runSha256 = "00".repeat(32))).join("\n")).to.include(
        "PROOF_TO_VERIFICATION",
      );
      expect(broken((e) => (e.verification.proof.proofBytesSha256 = "00".repeat(32))).join("\n")).to.include(
        "PROOF_TO_VERIFICATION",
      );
      expect(broken((e) => (e.verification.acceptance = "REJECTED")).join("\n")).to.include("PROOF_TO_VERIFICATION");
      expect(broken((e) => (e.verification.checks = [{ real: "success", tampered: "success" }])).join("\n")).to.include(
        "PROOF_TO_VERIFICATION",
      );
      expect(broken((e) => (e.verification.checks = [])).join("\n")).to.include("PROOF_TO_VERIFICATION");
    });

    it("breaks when the v2 record is not derived from these observations, is not a v2 record, or carries other digests", function () {
      expect(broken((e) => (e.record.derivedFrom = [e.record.derivedFrom[0]])).join("\n")).to.include(
        "OBSERVATIONS_TO_RECORD",
      );
      expect(broken((e) => (e.record.proof.proofBytesSha256 = "00".repeat(32))).join("\n")).to.include(
        "OBSERVATIONS_TO_RECORD",
      );
      expect(broken((e) => (e.record.lane = "SP1-PA3B")).join("\n")).to.include("OBSERVATIONS_TO_RECORD");
      expect(broken((e) => (e.record.schema = "walletwall.sp1-proof-exercise.v1")).join("\n")).to.include(
        "OBSERVATIONS_TO_RECORD",
      );
      expect(
        broken((e) => {
          e.record.assurance.level = "EDGE_PROBES_ONLY";
          e.record.assurance.continuousObservation = "ABSENT";
        }).join("\n"),
      ).to.include("OBSERVATIONS_TO_RECORD");
      expect(broken((e) => (e.record.assurance.enforcement = "STATED")).join("\n")).to.include(
        "OBSERVATIONS_TO_RECORD",
      );
    });

    it("carries partial attribution as a fact: it holds while the criterion's own classes are clean, and names every residue by count", function () {
      const i = inputsOf();
      const a = (i.exercise as ExerciseView).record.assurance;
      a.level = "CONTINUOUS_PARTIALLY_ATTRIBUTED";
      a.processAttribution = "PARTIAL";
      a.unattributedEvents = 19;
      a.unseenDestinations = 10;
      a.otherNamespaceEgress = 4;
      const chain = chainOf(i);
      expect(chain.holds).to.equal(true);
      const residue = chain.links.find((l) => l.id === "ATTRIBUTION_RESIDUE");
      expect(residue?.holds).to.equal(true);
      expect(residue?.detail).to.include("19 refused packet");
      expect(residue?.detail).to.include("10 send");
      expect(residue?.detail).to.include("4 send(s) or connect(s) from");
      expect(residue?.detail).to.include("complete attribution is not claimed");
      expect(residue?.detail).to.not.include("every attempt in the window has a seen outcome");
      expect(residue?.detail).to.include("to a resolver");
      expect(broken((e) => (e.record.assurance.unknownOutcomes = 1)).join("\n")).to.include("ATTRIBUTION_RESIDUE");
      expect(broken((e) => (e.record.assurance.unattributedOutsideWindow = 2)).join("\n")).to.include(
        "ATTRIBUTION_RESIDUE",
      );
    });

    it("never fails open: a residue count the record does not carry breaks the link", function () {
      for (const field of [
        "unknownOutcomes",
        "unattributedOutsideWindow",
        "unattributedEvents",
        "unseenDestinations",
        "otherNamespaceEgress",
        "attemptsInWindow",
        "refusedPackets",
      ] as const) {
        expect(
          broken((e) => ((e.record.assurance as unknown as Record<string, unknown>)[field] = null)).join("\n"),
          field,
        ).to.include("ATTRIBUTION_RESIDUE");
      }
    });

    it("breaks when the observer that watched the run is not the qualified one, or ran under another boundary", function () {
      expect(broken((e) => (e.run.observer.scriptSha256 = "00".repeat(32))).join("\n")).to.include(
        "QUALIFICATION_TO_OBSERVER",
      );
      expect(broken((e) => (e.run.observer.mode = "SELF_TEST")).join("\n")).to.include("QUALIFICATION_TO_OBSERVER");
      expect(broken((e) => (e.run.observer.boundary = "SELF_TEST_TABLE")).join("\n")).to.include("BOUNDARY_TO_RUN");
      expect(broken((e) => (e.run.observer.boundary = "OTHER")).join("\n")).to.include("BOUNDARY_TO_RUN");
      expect(broken((e) => (e.run.egress.condition = "EGRESS_OBSERVED")).join("\n")).to.include("BOUNDARY_TO_RUN");
    });

    it("breaks when the proof predates the manifest, or the attestation is not of this manifest or of the source commit", function () {
      expect(broken((e) => (e.run.timing.startedAtUtc = "2026-11-01T00:00:00Z")).join("\n")).to.include(
        "MANIFEST_BEFORE_PROOF",
      );
      expect(broken((e, i) => (i.preproof.value.manifest.sha256 = "00".repeat(32))).join("\n")).to.include(
        "MANIFEST_TO_ATTESTATION",
      );
      expect(broken((e, i) => (i.preproof.value.verdict = "PA3D_PREPROOF_ENVIRONMENT_REFUSED")).join("\n")).to.include(
        "MANIFEST_TO_ATTESTATION",
      );
      expect(broken((e, i) => (i.preproof.value.provingCheckout.commit = "c".repeat(40))).join("\n")).to.include(
        "MANIFEST_TO_ATTESTATION",
      );
    });

    it("binds the manifest and the attestation to commit ancestry, not only to stamps", function () {
      expect(broken((e, i) => (i.provenance.manifestInLaneCheckout = false)).join("\n")).to.include(
        "MANIFEST_IN_ATTESTED_CHECKOUT",
      );
      expect(broken((e, i) => (i.provenance.manifestInLaneCheckout = null)).join("\n")).to.include(
        "MANIFEST_IN_ATTESTED_CHECKOUT",
      );
      expect(broken((e, i) => (i.provenance.attestationInRunCheckout = false)).join("\n")).to.include(
        "ATTESTATION_IN_RUN_CHECKOUT",
      );
      expect(broken((e, i) => (i.provenance.runLaneCheckout = null)).join("\n")).to.include(
        "ATTESTATION_IN_RUN_CHECKOUT",
      );
      const chain = chainOf(inputsOf());
      expect(chain.links.find((l) => l.id === "MANIFEST_IN_ATTESTED_CHECKOUT")?.detail).to.include(
        preproof.laneCheckout.commit,
      );
      expect(broken((e, i) => (i.provenance.laneCheckout = "a".repeat(40))).join("\n")).to.include(
        "MANIFEST_IN_ATTESTED_CHECKOUT",
      );
      expect(chain.links.find((l) => l.id === "ATTESTATION_IN_RUN_CHECKOUT")?.detail).to.include("b".repeat(40));
    });
  });

  describe("the reproducibility statement", function () {
    it("claims statement reproducibility from equal public values and never proof-byte determinism", function () {
      const r = reproducibilityOf(inputsOf());
      expect(r.statement).to.equal("REPRODUCED");
      expect(r.publicValuesSha256.expected).to.equal(manifest.statement.expectedPublicValues.sha256);
      expect(r.publicValuesSha256.observed).to.equal(manifest.statement.expectedPublicValues.sha256);
      expect(r.proofBytes.pa3b).to.equal(PA3B_PROOF_SHA);
      expect(r.proofBytes.pa3d).to.equal("ab".repeat(32));
      expect(r.proofBytes.identical).to.equal(false);
      expect(r.proofBytes.determinism).to.equal("NOT_CLAIMED");
      expect(r.proofBytes.why).to.include("randomized");
      const i = inputsOf();
      (i.exercise as ExerciseView).run.proof.publicValuesSha256 = "00".repeat(32);
      expect(reproducibilityOf(i).statement).to.equal("NOT_REPRODUCED");
    });
  });

  describe("the record and its validator", function () {
    it("derives PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED from a consistent exercise, and refuses to derive without a proof", function () {
      const r = pa3dRecordFrom(inputsOf());
      expect(r.schema).to.equal(RECORD_SCHEMA);
      expect(r.state).to.equal("PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED");
      expect(r.blockers).to.deep.equal([]);
      expect(r.productionSp1Binding).to.equal("NOT_ESTABLISHED");
      expect(r.next).to.deep.equal({ lane: "SP1-PA3E", what: "design review", started: false });
      expect(r.kind).to.include("exercise record");
      expect(r.kind).to.include("not a production binding record");
      expect(r.provenance).to.deep.equal(inputsOf().provenance);
      expect(r.derivedFrom.map((d) => d.path)).to.include(MANIFEST_REL);
      expect(r.derivedFrom.map((d) => d.path)).to.include(preproofRel);
      expect(r.negativeControls.length).to.equal(PA3D_NEGATIVE_CONTROLS.length);
      for (const c of r.negativeControls.filter((x) => x.kind === "VALIDATOR")) expect(c.outcome).to.equal("REFUSED");
      for (const c of r.negativeControls.filter((x) => x.kind === "VERIFIER"))
        expect(c.outcome).to.equal("EXECUTED_BY_TEST_SUITE");
      assert.throws(() => pa3dRecordFrom(inputsOf(null)), /no v2 exercise|NO_EXERCISE/);
    });

    it("derives the blocked states honestly: a broken chain, a refused attestation, a blocked gate", function () {
      const i = inputsOf();
      (i.exercise as ExerciseView).verification.acceptance = "REJECTED";
      const r = pa3dRecordFrom(i);
      expect(r.state).to.equal("PA3D_PROOF_GENERATED_VERIFICATION_BLOCKED");
      expect(r.blockers.join("\n")).to.include("PROOF_TO_VERIFICATION");
      const refused = inputsOf();
      refused.preproof.value.verdict = "PA3D_PREPROOF_ENVIRONMENT_REFUSED";
      refused.preproof.value.refusals = ["HOST_BINARY_DIFFERS: x"];
      expect(pa3dRecordFrom(refused).state).to.equal("PA3D_PREPROOF_ENVIRONMENT_REFUSED");
      const gated = inputsOf();
      gated.manifest.value.acquisitionGate = { verdict: "BLOCKED", blockers: ["x"] };
      expect(pa3dRecordFrom(gated).state).to.equal("PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE");
    });

    it("accepts what it derives and refuses any leaf that differs, an unknown field or a missing one", function () {
      const i = inputsOf();
      const r = pa3dRecordFrom(i);
      const text = serializePa3dRecord(r);
      expect(text.endsWith("}\n")).to.equal(true);
      expect(pa3dRecordErrors(JSON.parse(text), i)).to.deep.equal([]);
      const graded = clone(r);
      graded.state = "PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED";
      const j = inputsOf();
      (j.exercise as ExerciseView).run.inputsSha256 = "00".repeat(32);
      expect(pa3dRecordErrors(graded, j).join("\n")).to.include("state");
      expect(pa3dRecordErrors({ ...clone(r), extra: 1 }, i).join("\n")).to.include("extra");
      const fewer = clone(r) as Partial<Pa3dRecord>;
      delete fewer.chain;
      expect(pa3dRecordErrors(fewer, i).join("\n")).to.include("chain");
      expect(pa3dRecordErrors(null, i)).to.not.deep.equal([]);
      const binding = clone(r);
      binding.productionSp1Binding = "ESTABLISHED";
      expect(pa3dRecordErrors(binding, i).join("\n")).to.include("PRODUCTION_SP1_BINDING");
    });

    it("re-runs every validator-class negative control; each is refused by the very link or state it names", function () {
      const results = runPa3dNegativeControls(inputsOf());
      expect(results.length).to.equal(12);
      for (const r of results) {
        expect(r.outcome, r.id).to.equal("REFUSED");
        expect(r.refusedBy, r.id).to.include(r.expectedRefusal);
        expect(r.refusedBy[0]).to.not.equal("PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED");
      }
      // A control whose mutation is undone is not refused: the controls test the validator, not the fixtures.
      const i = inputsOf();
      expect(chainOf(i).holds).to.equal(true);
    });
  });

  describe("the committed record", function () {
    it("is stated by the gate document: the heading names the lane, its section the state, the binding, the run and the residue", function () {
      if (!existsSync(RECORD_REL)) this.skip();
      const committed = JSON.parse(lf(readFileSync(RECORD_REL, "utf8"))) as Pa3dRecord;
      const doc = lf(readFileSync("docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md", "utf8"));
      expect(doc.split("\n")[0]).to.include("SP1-PA3D");
      const start = doc.indexOf("\n## SP1-PA3D:");
      expect(start).to.be.greaterThan(0);
      const section = doc.slice(start, doc.indexOf("\n## ", start + 5));
      expect(section).to.include(`State: \`${committed.state}\``);
      expect(section).to.include("`PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`");
      expect(section).to.include(committed.exercise?.token ?? "no token");
      expect(section).to.include(committed.exercise?.run.sha256 ?? "no run");
      expect(section).to.include(committed.manifest.sha256);
      expect(section).to.include(committed.exercise?.record.assurance.level ?? "no level");
      expect(section).to.include(`${committed.exercise?.record.assurance.unattributedEvents} refused packets`);
      expect(section).to.include(`${committed.exercise?.record.assurance.otherNamespaceEgress} attempts`);
      expect(section).to.include("NOT_CLAIMED");
      expect(section).to.include("SP1-PA3E");
      expect(section).to.not.include("chronyd` was inactive");
    });

    it("when committed, is what the committed evidence derives, and its state is the attributed-and-verified one", function () {
      if (!existsSync(RECORD_REL)) this.skip();
      const inputs = pa3dInputsFromRepo(".");
      const committedText = lf(readFileSync(RECORD_REL, "utf8"));
      const committed = JSON.parse(committedText) as Pa3dRecord;
      expect(pa3dRecordErrors(committed, inputs)).to.deep.equal([]);
      expect(serializePa3dRecord(pa3dRecordFrom(inputs))).to.equal(committedText);
      expect(committed.state).to.equal("PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED");
      expect(committed.reproducibility.statement).to.equal("REPRODUCED");
      expect(committed.reproducibility.proofBytes.determinism).to.equal("NOT_CLAIMED");
      expect(committed.provenance.manifestInLaneCheckout).to.equal(true);
      expect(committed.provenance.attestationInRunCheckout).to.equal(true);
      // The residue of this run, re-derived from the committed events by the frozen attribution library.
      expect(committed.exercise?.record.assurance.otherNamespaceEgress).to.equal(3);
      expect(committed.exercise?.record.assurance.unattributedEvents).to.equal(19);
      expect(committed.exercise?.record.assurance.unseenDestinations).to.equal(10);
    });
  });
});
