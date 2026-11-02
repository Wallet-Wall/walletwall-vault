/**
 * SP1-PA3D, Phases 6-8: the exercise record (evidence/zk/sp1-impl/pa3d-exercise-record.json), derived from committed
 * evidence alone: the manifest (authored before the proof), the pre-proof attestation, the one v2 exercise (its run
 * observation, its verification observation and the v2 record SP1-PA3D0's directory accepts) and the observer
 * qualification the run stood on. It holds the ATTRIBUTION CHAIN, link by link, each a comparison of committed digests
 * or of commit ancestry (the source commit to the manifest, the manifest to the attestation and to the checkout the
 * attestation names, the source commit to the run, the attestation to the checkout the run names, the program, the
 * inputs and the statement's public values to the run and its proof, the circuit to the run, the proof to the
 * verification, the observations to the v2 record, the attribution residue by count, the qualification to the observer
 * that watched the run, the declared boundary to the run's condition, the manifest's stamp before the proof's); the
 * REPRODUCIBILITY statement (the statement's public values reproduced; proof-byte determinism not claimed); the
 * NEGATIVE CONTROLS, those of the validator class re-run here on mutated copies of the evidence, those of the verifier
 * class executed by the test suite on a development chain; and the STATE, recomputed from facts. It is a v2 proof
 * exercise record, not a production binding record: PRODUCTION_SP1_BINDING = NOT_ESTABLISHED. Research prototype. Not
 * audited.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PROOF_INVALID } from "./sp1-chain-execution";
import { serializeJson } from "./sp1-circuit-acquisition";
import type { ArchiveMember } from "./sp1-circuit-archive";
import { committedProductionAnchor, productionArchiveEvidenceOf } from "./sp1-circuit-tooling";
import { observerEvidenceErrors, type BoundaryRule, type ObserverExpectations } from "./sp1-egress-attribution";
import { QUALIFICATION_REL, leafDifferences } from "./sp1-observer-qualification";
import {
  FINAL_STATES,
  LANE,
  MANIFEST_REL,
  NEXT_LANE,
  PREVIOUS_LANE,
  PRODUCTION_SP1_BINDING,
  REPOSITORY_ID,
  manifestContextFromRepo,
  manifestErrors,
  type FinalState,
  type Manifest,
  type ManifestContext,
} from "./sp1-pa3d-exercise";
import { preproofErrors, preproofObservationRel, type PreproofObservation } from "./sp1-pa3d-preproof";
import {
  ATTRIBUTED_RUN_SCRIPT_REL,
  EGRESS_DISABLED,
  EXERCISE_RECORD_SCHEMA_V2,
  RUN_SCHEMA_V2,
  exerciseExpectations,
  productionExerciseEvidence,
  type AttributedProofExerciseRecord,
  type AttributedRunObservation,
  type VerificationObservation,
} from "./sp1-proof-exercise";

export const RECORD_SCHEMA = "walletwall.sp1-pa3d-exercise-record.v1";
export const RECORD_REL = "evidence/zk/sp1-impl/pa3d-exercise-record.json";
export const RECORD_JSON_SCHEMA_REL = "evidence/zk/schema/sp1-pa3d-exercise-record.v1.schema.json";
/** SP1-PA3B's proof of the same statement: the bytes PA3D's are compared with (never expected equal). */
export const PA3B_RUN_REL = "evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.raw.json";
export const RECORD_KIND =
  "a PA3D v2 proof exercise record: one real attributed proof of the designated program, independently verified on a development chain, bound to its source and its observer qualification by committed digests; not a production binding record";
export const NEGATIVE_CONTROL_SUITE = "test/Sp1Pa3dNegativeControls.test.ts";

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const isObject = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const isCount = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0;
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const byPath = <T extends { path: string }>(xs: readonly T[]) => [...xs].sort((a, b) => (a.path < b.path ? -1 : 1));
const seconds = (utc: string) => Date.parse(utc) / 1000;

// ---------------------------------------------------------------------------------------------------------------
// The views: what the chain reads of each committed file (projected by pa3dInputsFromRepo after the file's own
// validator accepted it; built by hand in tests)
// ---------------------------------------------------------------------------------------------------------------

export interface RunView {
  path: string;
  sha256: string;
  schema: string;
  host: string;
  measuredAtUtc: string;
  source: { commit: string; zkvmHostTree: string };
  toolSha256: string;
  programVKey: string;
  hostExecutableSha256: string;
  inputsSha256: string;
  archiveRecordSha256: string;
  installedMembers: ArchiveMember[];
  gnarkDigest: string;
  proverMode: string;
  proof: { vkey: string; selector: string; publicValues: string; publicValuesSha256: string; proofBytesSha256: string };
  egress: { condition: string; probesRefused: boolean; probes: number };
  observer: { scriptSha256: string; mode: string; boundary: string; bootId: string };
  timing: { startedAtUtc: string; finishedAtUtc: string; gateSeconds: number };
}

export interface VerificationView {
  path: string;
  sha256: string;
  runSha256: string;
  acceptance: string;
  /** The chain's verdicts as recorded: `success`, or `revert <selector>`. */
  checks: { real: string; tampered: string }[];
  proof: { publicValuesSha256: string; proofBytesSha256: string };
  verifierVersion: string;
  runtimeCodeKeccak: string;
}

/**
 * The v2 record's egress assurance as derived (scripts/lib/sp1-egress-attribution.ts assuranceOf), with its residue
 * by count; a count the record does not carry is null, and null never holds a link (the view fails closed).
 */
export interface AssuranceView {
  level: string;
  continuousObservation: string;
  processAttribution: string;
  enforcement: string;
  edgeProbes: string;
  attemptsInWindow: number | null;
  refusedPackets: number | null;
  /** Refused packets inside the window that no observed attempt sent (refused by the boundary, not sent past it). */
  unattributedEvents: number | null;
  unattributedOutsideWindow: number | null;
  /**
   * Attempts to a resolver (any namespace) or from the host namespace to beyond the VM whose outcome the capture does
   * not show: the class the frozen derivation names as possibly hiding a packet past the boundary.
   */
  unknownOutcomes: number | null;
  /** Sends whose destination the capture cannot read (packet, raw, AF_XDP sockets): counted, never read. */
  unseenDestinations: number | null;
  /**
   * Sends or connects inside the window from a namespace that is neither the host's nor the proof container's, to a
   * destination beyond the VM, whose outcome was SENT, CONNECTED or CLOSED_UNREFUSED: the frozen leak rule does not
   * count them (it takes other namespaces to exit through the host's forward hook, which the boundary drops), so they
   * are re-derived here from the committed events and named as residue; the inet boundary never saw them.
   */
  otherNamespaceEgress: number | null;
}

export interface RecordView {
  path: string;
  sha256: string;
  schema: string;
  lane: string;
  proof: { publicValuesSha256: string; proofBytesSha256: string };
  assurance: AssuranceView;
  derivedFrom: string[];
}

export interface ExerciseView {
  token: string;
  run: RunView;
  verification: VerificationView;
  record: RecordView;
}

/** Commit ancestry the chain binds instead of trusting stamps: what each checkout the evidence names holds. */
export interface Provenance {
  /** The lane checkout the attestation was made from (its recorded commit). */
  laneCheckout: string | null;
  /** That commit is an ancestor of this checkout and holds the manifest at its committed digest (null: not checkable). */
  manifestInLaneCheckout: boolean | null;
  /** The lane checkout the run's platform lines name (`laneCheckout=<sha>`). */
  runLaneCheckout: string | null;
  /** That commit is an ancestor of this checkout and holds the attestation at its committed digest (null: not checkable). */
  attestationInRunCheckout: boolean | null;
}

export interface Pa3dInputs {
  manifest: { path: string; sha256: string; value: Manifest; errors: string[] };
  preproof: { path: string; sha256: string; value: PreproofObservation; errors: string[] };
  qualification: { path: string; sha256: string; observerScriptSha256: string; state: string };
  provenance: Provenance;
  /** SP1-PA3B's proof bytes digest, or null when its run is not committed. */
  pa3bProofBytesSha256: string | null;
  /** The one v2 exercise made from the manifest's source commit on its host, or null when none is committed. */
  exercise: ExerciseView | null;
  /** Why the exercise directory, or the one exercise, is refused by its own validators (empty when accepted). */
  exerciseErrors: string[];
}

// ---------------------------------------------------------------------------------------------------------------
// The boundary a run's observer recorded, classified from the rules themselves (never from a label)
// ---------------------------------------------------------------------------------------------------------------

export type BoundaryClass = "COMPLETE_EGRESS_BOUNDARY" | "SELF_TEST_TABLE" | "OTHER";

/**
 * COMPLETE_EGRESS_BOUNDARY when the declared table (as the observer read it) refuses a resolver address at the output
 * hook, accepts the host's own addresses there (`fib daddr type == local`, the operator checked: its inverse is another
 * table), rejects every other output (a tcp reset rule and an admin-prohibited rule) and drops at the forward hook,
 * with no TEST-NET-1 rule; SELF_TEST_TABLE when it refuses TEST-NET-1 and nothing else; otherwise OTHER.
 */
export function boundaryClassOf(rules: readonly BoundaryRule[]): BoundaryClass {
  const output = rules.filter((r) => r.hook === "output");
  const forward = rules.filter((r) => r.hook === "forward");
  const has = (rs: readonly BoundaryRule[], verdict: BoundaryRule["verdict"], ...needles: string[]) =>
    rs.some((r) => r.verdict === verdict && needles.every((n) => r.expr.includes(n)));
  const testNet = rules.some((r) => /192.0.2./.test(r.expr));
  const resolverRefused = has(output, "reject", '"field":"daddr"', '"op":"=="');
  const complete =
    resolverRefused &&
    has(output, "accept", '"fib"', '"op":"=="', '"right":"local"') &&
    has(output, "reject", "tcp reset") &&
    has(output, "reject", "admin-prohibited") &&
    has(forward, "drop") &&
    !testNet;
  const selfTest = testNet && !has(output, "accept", '"fib"') && forward.length === 0;
  if (complete && !selfTest) return "COMPLETE_EGRESS_BOUNDARY";
  if (selfTest && !complete) return "SELF_TEST_TABLE";
  return "OTHER";
}

/** The rules' identity across the observer's snapshots (counters excluded): the class only when every snapshot agrees. */
export function boundaryOfSnapshots(boundary: readonly { n: number; rules: readonly BoundaryRule[] }[]): BoundaryClass {
  if (boundary.length === 0) return "OTHER";
  const identity = (rules: readonly BoundaryRule[]) =>
    JSON.stringify(rules.map((r) => [r.family, r.table, r.chain, r.hook, r.verdict, r.handle, r.expr]));
  const first = identity(boundary[0].rules);
  if (!boundary.every((b) => identity(b.rules) === first)) return "OTHER";
  return boundaryClassOf(boundary[0].rules);
}

// ---------------------------------------------------------------------------------------------------------------
// The attribution chain
// ---------------------------------------------------------------------------------------------------------------

export interface ChainLink {
  id: string;
  from: string;
  to: string;
  holds: boolean;
  detail: string;
}

export interface Chain {
  links: ChainLink[];
  holds: boolean;
  blockers: string[];
}

/** Every link of the chain, each a comparison of committed values; `blockers` names each broken link. */
export function chainOf(inputs: Pa3dInputs): Chain {
  const m = inputs.manifest.value;
  const p = inputs.preproof.value;
  const pv = inputs.provenance;
  const e = inputs.exercise;
  const links: ChainLink[] = [];
  const link = (id: string, from: string, to: string, holds: boolean, detail: string) =>
    links.push({ id, from, to, holds, detail });
  const attributedTool = m.tools.find((t) => t.path === ATTRIBUTED_RUN_SCRIPT_REL)?.sha256 ?? null;

  link(
    "SOURCE_TO_MANIFEST",
    `source commit ${m.source.commit}`,
    `manifest ${inputs.manifest.sha256}`,
    inputs.manifest.errors.length === 0 && HEX64.test(inputs.manifest.sha256),
    inputs.manifest.errors.length === 0
      ? "the manifest validates against the checkout and names the source commit"
      : `the manifest is refused: ${inputs.manifest.errors.join("; ")}`,
  );
  const attestationOfManifest = p.manifest.sha256 === inputs.manifest.sha256;
  const attestationValid = inputs.preproof.errors.length === 0 && p.verdict === "PA3D_PREPROOF_ENVIRONMENT_VALID";
  link(
    "MANIFEST_TO_ATTESTATION",
    `manifest ${inputs.manifest.sha256}`,
    `pre-proof attestation ${inputs.preproof.sha256} (${p.verdict})`,
    attestationOfManifest && attestationValid && p.provingCheckout.commit === m.source.commit,
    !attestationOfManifest
      ? `the attestation is of another manifest (${p.manifest.sha256})`
      : !attestationValid
        ? `the attestation is ${p.verdict}${inputs.preproof.errors.length > 0 ? ` and refused: ${inputs.preproof.errors.join("; ")}` : ""}`
        : p.provingCheckout.commit !== m.source.commit
          ? `the attested proving checkout ${p.provingCheckout.commit} is not the source commit`
          : "the attestation is of this manifest, VALID, and attests a clean checkout of the source commit",
  );
  link(
    "MANIFEST_IN_ATTESTED_CHECKOUT",
    `the lane checkout the attestation names (${pv.laneCheckout ?? "none"})`,
    `manifest ${inputs.manifest.sha256}`,
    pv.manifestInLaneCheckout === true && pv.laneCheckout === p.laneCheckout.commit,
    pv.manifestInLaneCheckout === true && pv.laneCheckout === p.laneCheckout.commit
      ? `commit ${pv.laneCheckout} is an ancestor of this checkout and holds the manifest at its committed digest: the attestation was made from a checkout holding this manifest`
      : pv.manifestInLaneCheckout === null
        ? `commit ${pv.laneCheckout ?? "none"} cannot be checked here (not a commit of this repository, or not an ancestor)`
        : `commit ${pv.laneCheckout ?? "none"} does not hold this manifest: the attestation names a checkout the manifest was not in`,
  );
  if (e === null) {
    link(
      "SOURCE_TO_RUN",
      `source commit ${m.source.commit}`,
      "run observation",
      false,
      `no v2 exercise is committed${inputs.exerciseErrors.length > 0 ? `: ${inputs.exerciseErrors.join("; ")}` : ""}`,
    );
    return { links, holds: false, blockers: links.filter((l) => !l.holds).map((l) => `${l.id}: ${l.detail}`) };
  }
  const r = e.run;
  const v = e.verification;
  const rec = e.record;
  link(
    "SOURCE_TO_RUN",
    `source commit ${m.source.commit}`,
    `run observation ${r.sha256} (${r.path})`,
    r.source.commit === m.source.commit &&
      r.source.zkvmHostTree === m.statement.zkvmHostTree &&
      r.toolSha256 === attributedTool &&
      r.schema === RUN_SCHEMA_V2 &&
      r.host === m.environment.hostLabel &&
      inputs.exerciseErrors.length === 0,
    r.source.commit !== m.source.commit
      ? `the run was made from ${r.source.commit}`
      : r.toolSha256 !== attributedTool
        ? `the run was made by another tool (${r.toolSha256})`
        : r.schema !== RUN_SCHEMA_V2
          ? `the run is ${r.schema}, not v2`
          : r.host !== m.environment.hostLabel
            ? `the run is of host ${r.host}`
            : inputs.exerciseErrors.length > 0
              ? `the exercise is refused by its validators: ${inputs.exerciseErrors.join("; ")}`
              : "the run was made from the source commit, on the manifest's host, by the committed attributed tool, and its exercise is accepted",
  );
  link(
    "ATTESTATION_IN_RUN_CHECKOUT",
    `the lane checkout the run's platform lines name (${pv.runLaneCheckout ?? "none"})`,
    `pre-proof attestation ${inputs.preproof.sha256}`,
    pv.attestationInRunCheckout === true && pv.runLaneCheckout !== null,
    pv.attestationInRunCheckout === true && pv.runLaneCheckout !== null
      ? `commit ${pv.runLaneCheckout} is an ancestor of this checkout and holds the attestation at its committed digest: the run names a checkout in which the VALID attestation already stood`
      : pv.runLaneCheckout === null
        ? "the run names no lane checkout (no laneCheckout=<sha> platform line)"
        : pv.attestationInRunCheckout === null
          ? `commit ${pv.runLaneCheckout} cannot be checked here (not a commit of this repository, or not an ancestor)`
          : `commit ${pv.runLaneCheckout} does not hold this attestation: the run names a checkout the attestation was not in`,
  );
  link(
    "PROGRAM_TO_RUN",
    `program ${m.statement.programVKey}, host binary ${m.prover.hostBinary.sha256}`,
    "the run's anchor and host executable",
    r.programVKey === m.statement.programVKey &&
      r.proof.vkey === m.statement.programVKey &&
      r.hostExecutableSha256 === m.prover.hostBinary.sha256 &&
      r.proverMode === m.prover.mode,
    r.programVKey !== m.statement.programVKey || r.proof.vkey !== m.statement.programVKey
      ? `the run proved under ${r.programVKey} / ${r.proof.vkey}`
      : r.hostExecutableSha256 !== m.prover.hostBinary.sha256
        ? `the run's host binary is ${r.hostExecutableSha256}`
        : r.proverMode !== m.prover.mode
          ? `the run's prover mode is ${r.proverMode}`
          : "the run proved the designated program with the canonical host binary in the planned mode",
  );
  link(
    "INPUTS_TO_RUN",
    `inputs ${m.statement.inputs.sha256}`,
    `the run's inputs ${r.inputsSha256}`,
    r.inputsSha256 === m.statement.inputs.sha256,
    r.inputsSha256 === m.statement.inputs.sha256
      ? "the run read the committed input fixture"
      : "the run read other inputs",
  );
  const pvSha = m.statement.expectedPublicValues.sha256;
  const pvHex = m.statement.expectedPublicValues.hex;
  const pvObserved = /^0x(?:[0-9a-f]{2})+$/.test(r.proof.publicValues)
    ? sha256(Buffer.from(r.proof.publicValues.slice(2), "hex"))
    : null;
  link(
    "STATEMENT_TO_PUBLIC_VALUES",
    `expected public values ${pvSha}`,
    `the proof's public values ${r.proof.publicValuesSha256}`,
    r.proof.publicValuesSha256 === pvSha && r.proof.publicValues === pvHex && pvObserved === pvSha,
    r.proof.publicValuesSha256 === pvSha && r.proof.publicValues === pvHex && pvObserved === pvSha
      ? "the proof commits to the statement's public values, byte for byte"
      : `the proof commits to other public values (${r.proof.publicValuesSha256}; recomputed ${pvObserved ?? "unreadable"})`,
  );
  link(
    "CIRCUIT_TO_RUN",
    `circuit ${m.circuit.version} (archive record ${m.circuit.archiveRecord.sha256}, gnark ${m.circuit.gnark.digest})`,
    "the run's archive record, installed members and gnark image",
    r.archiveRecordSha256 === m.circuit.archiveRecord.sha256 &&
      same(byPath(r.installedMembers), byPath(m.circuit.members)) &&
      r.gnarkDigest === m.circuit.gnark.digest &&
      r.proof.selector === m.circuit.verifier.selector,
    r.archiveRecordSha256 !== m.circuit.archiveRecord.sha256
      ? `the run ran from another archive record (${r.archiveRecordSha256})`
      : !same(byPath(r.installedMembers), byPath(m.circuit.members))
        ? "the installed members the gate verified are not the archive record's"
        : r.gnarkDigest !== m.circuit.gnark.digest
          ? `the run used another gnark image (${r.gnarkDigest})`
          : r.proof.selector !== m.circuit.verifier.selector
            ? `the proof's selector ${r.proof.selector} is not the verifier's`
            : "the run proved from the manifest's circuit, members and gnark image under the verifier's key",
  );
  const tamperedRefused =
    v.checks.length > 0 && v.checks.every((c) => c.real === "success" && c.tampered === `revert ${PROOF_INVALID}`);
  link(
    "PROOF_TO_VERIFICATION",
    `proof ${r.proof.proofBytesSha256} in run ${r.sha256}`,
    `verification ${v.sha256} (${v.acceptance}, ${v.checks.length} check(s))`,
    v.runSha256 === r.sha256 &&
      v.proof.proofBytesSha256 === r.proof.proofBytesSha256 &&
      v.proof.publicValuesSha256 === r.proof.publicValuesSha256 &&
      v.acceptance === "ACCEPTED" &&
      tamperedRefused &&
      v.verifierVersion === m.circuit.verifier.version &&
      v.runtimeCodeKeccak === m.circuit.verifier.runtimeCodeKeccak,
    v.runSha256 !== r.sha256
      ? `the verification binds another run (${v.runSha256})`
      : v.proof.proofBytesSha256 !== r.proof.proofBytesSha256 ||
          v.proof.publicValuesSha256 !== r.proof.publicValuesSha256
        ? "the verification names other proof digests"
        : v.acceptance !== "ACCEPTED"
          ? `the designated verifier did not accept (${v.acceptance})`
          : !tamperedRefused
            ? "not every check accepted the proof and refused its tampered copy"
            : v.verifierVersion !== m.circuit.verifier.version ||
                v.runtimeCodeKeccak !== m.circuit.verifier.runtimeCodeKeccak
              ? "the verification was not through the designated verifier"
              : "the designated verifier accepted the proof and refused its tampered copy, on the run's committed bytes",
  );
  link(
    "OBSERVATIONS_TO_RECORD",
    `run ${r.path}, verification ${v.path}`,
    `v2 record ${rec.sha256} (${rec.path})`,
    rec.schema === EXERCISE_RECORD_SCHEMA_V2 &&
      rec.lane === LANE &&
      same([...rec.derivedFrom].sort(), [r.path, v.path].sort()) &&
      rec.proof.proofBytesSha256 === r.proof.proofBytesSha256 &&
      rec.proof.publicValuesSha256 === r.proof.publicValuesSha256 &&
      rec.assurance.continuousObservation === "PRESENT" &&
      rec.assurance.enforcement === "STATED_AND_COUNTED" &&
      rec.assurance.edgeProbes === "REFUSED_BEFORE_AND_AFTER_AND_OBSERVED" &&
      (rec.assurance.level === "CONTINUOUS_ATTRIBUTED" || rec.assurance.level === "CONTINUOUS_PARTIALLY_ATTRIBUTED"),
    rec.schema !== EXERCISE_RECORD_SCHEMA_V2 || rec.lane !== LANE
      ? `the record is ${rec.schema} of ${rec.lane}`
      : !same([...rec.derivedFrom].sort(), [r.path, v.path].sort())
        ? `the record is derived from other observations (${rec.derivedFrom.join(", ")})`
        : rec.proof.proofBytesSha256 !== r.proof.proofBytesSha256 ||
            rec.proof.publicValuesSha256 !== r.proof.publicValuesSha256
          ? "the record carries other proof digests"
          : rec.assurance.continuousObservation !== "PRESENT" ||
              rec.assurance.enforcement !== "STATED_AND_COUNTED" ||
              rec.assurance.edgeProbes !== "REFUSED_BEFORE_AND_AFTER_AND_OBSERVED" ||
              (rec.assurance.level !== "CONTINUOUS_ATTRIBUTED" &&
                rec.assurance.level !== "CONTINUOUS_PARTIALLY_ATTRIBUTED")
            ? `the record's egress assurance is ${rec.assurance.level} (continuous observation ${rec.assurance.continuousObservation}, enforcement ${rec.assurance.enforcement}, edge probes ${rec.assurance.edgeProbes}): not continuous, counted and observed`
            : `the v2 record derives from these two observations with continuous observation, counted enforcement and ${rec.assurance.processAttribution} process attribution (${rec.assurance.level})`,
  );
  // Partial attribution is a fact the derivation computes, never hidden. The frozen derivation's criterion is narrow
  // and is stated as such: it holds when no attempt to a resolver (any namespace), and none from the host namespace to
  // beyond the VM, has an unknown outcome, and when nothing unattributed lies outside the window. Everything else the
  // capture shows but the criterion does not judge is counted here as residue: refused packets no observed attempt
  // sent, sends of unseen destination, and sends or connects from other namespaces to beyond the VM that the inet
  // boundary never saw. A count the record does not carry breaks the link. Complete attribution is not claimed where
  // the record does not state it.
  const a = rec.assurance;
  const counts = [
    a.attemptsInWindow,
    a.refusedPackets,
    a.unattributedEvents,
    a.unattributedOutsideWindow,
    a.unknownOutcomes,
    a.unseenDestinations,
    a.otherNamespaceEgress,
  ];
  const counted = counts.every(isCount);
  link(
    "ATTRIBUTION_RESIDUE",
    `the run's ${a.attemptsInWindow} attempts in the window and ${a.refusedPackets} refused packets`,
    `residue: ${a.unattributedEvents} refused packets no attempt sent, ${a.unseenDestinations} sends of unseen destination, ${a.otherNamespaceEgress} other-namespace sends or connects beyond the VM, ${a.unknownOutcomes} unknown outcomes, ${a.unattributedOutsideWindow} unattributed outside the window`,
    counted && a.unknownOutcomes === 0 && a.unattributedOutsideWindow === 0,
    !counted
      ? "the record does not carry every residue count: nothing is taken as zero"
      : a.unknownOutcomes !== 0
        ? `${a.unknownOutcomes} attempt(s) to a resolver, or from the host namespace to beyond the VM, have no seen outcome: a packet may have passed the boundary unobserved`
        : a.unattributedOutsideWindow !== 0
          ? `${a.unattributedOutsideWindow} refused packet(s) outside the window are unattributed`
          : `attribution is ${a.processAttribution}: no attempt to a resolver, and none from the host namespace to beyond the VM, has an unseen outcome, the classes the frozen derivation judges; the residue it does not judge is counted, not excused: ${a.unattributedEvents} refused packet(s) that no observed attempt sent (refused by the boundary, not sent past it), ${a.unseenDestinations} send(s) of unseen destination (packet, raw or AF_XDP sockets, whose destination the capture cannot read), ${a.otherNamespaceEgress} send(s) or connect(s) from namespaces neither the host's nor the proof container's to addresses beyond the VM that were sent or closed and never refused (an exit the inet boundary does not see); complete attribution is ${a.processAttribution === "COMPLETE" ? "stated by the v2 record" : "not claimed"}`,
  );
  link(
    "QUALIFICATION_TO_OBSERVER",
    `observer qualification ${inputs.qualification.sha256} (observer ${inputs.qualification.observerScriptSha256})`,
    `the observer that watched the run (${r.observer.scriptSha256}, ${r.observer.mode})`,
    inputs.qualification.state === "OBSERVER_QUALIFIED_FOR_PA3D" &&
      inputs.qualification.sha256 === m.environment.qualification.sha256 &&
      r.observer.scriptSha256 === inputs.qualification.observerScriptSha256 &&
      r.observer.mode === "RUN",
    inputs.qualification.state !== "OBSERVER_QUALIFIED_FOR_PA3D"
      ? `the qualification is ${inputs.qualification.state}`
      : inputs.qualification.sha256 !== m.environment.qualification.sha256
        ? "the qualification is not the one the manifest stands on"
        : r.observer.scriptSha256 !== inputs.qualification.observerScriptSha256
          ? "the run was watched by an observer other than the qualified one"
          : r.observer.mode !== "RUN"
            ? `the observer ran in ${r.observer.mode} mode`
            : "the qualified observer, byte-identical, watched the run in RUN mode",
  );
  link(
    "BOUNDARY_TO_RUN",
    `planned boundary ${m.plan.observer.boundary}`,
    `the run's table (${r.observer.boundary}) and condition ${r.egress.condition}`,
    r.observer.boundary === m.plan.observer.boundary &&
      r.egress.condition === EGRESS_DISABLED &&
      r.egress.probesRefused,
    r.observer.boundary !== m.plan.observer.boundary
      ? `the run stood under ${r.observer.boundary}`
      : r.egress.condition !== EGRESS_DISABLED || !r.egress.probesRefused
        ? `the run's egress condition is ${r.egress.condition} (${r.egress.probes} probes)`
        : `the complete egress boundary stood, classified from the rules the observer recorded in every snapshot, and every one of the ${r.egress.probes} edge probes was refused`,
  );
  const before =
    seconds(m.startedAtUtc) <= seconds(r.timing.startedAtUtc) &&
    seconds(r.timing.startedAtUtc) <= seconds(r.timing.finishedAtUtc);
  link(
    "MANIFEST_BEFORE_PROOF",
    `manifest started ${m.startedAtUtc}`,
    `proof gate ${r.timing.startedAtUtc} .. ${r.timing.finishedAtUtc} (${r.timing.gateSeconds} s)`,
    before,
    before
      ? "the manifest's start stamp precedes the gate's (the stamps are the operator's; the ancestry links above bind the order by commits)"
      : "the proof began before the manifest was authored",
  );
  return {
    links,
    holds: links.every((l) => l.holds),
    blockers: links.filter((l) => !l.holds).map((l) => `${l.id}: ${l.detail}`),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Reproducibility (Phase 8): the statement, not the bytes
// ---------------------------------------------------------------------------------------------------------------

export interface Reproducibility {
  statement: "REPRODUCED" | "NOT_REPRODUCED" | "NO_PROOF";
  publicValuesSha256: { expected: string; observed: string | null; source: string };
  proofBytes: {
    pa3b: string | null;
    pa3d: string | null;
    identical: boolean;
    determinism: "NOT_CLAIMED";
    why: string;
  };
}

export function reproducibilityOf(inputs: Pa3dInputs): Reproducibility {
  const expected = inputs.manifest.value.statement.expectedPublicValues.sha256;
  const observed = inputs.exercise?.run.proof.publicValuesSha256 ?? null;
  const pa3d = inputs.exercise?.run.proof.proofBytesSha256 ?? null;
  return {
    statement: observed === null ? "NO_PROOF" : observed === expected ? "REPRODUCED" : "NOT_REPRODUCED",
    publicValuesSha256: {
      expected,
      observed,
      source: inputs.manifest.value.statement.expectedPublicValues.source.path,
    },
    proofBytes: {
      pa3b: inputs.pa3bProofBytesSha256,
      pa3d,
      identical: pa3d !== null && pa3d === inputs.pa3bProofBytesSha256,
      determinism: "NOT_CLAIMED",
      why: "Groth16 proving is randomized, so two honest proofs of one statement differ in bytes; one proof was authorized here, so no second run of this environment compares, and SP1-PA3B's proof (another commit, another day) is compared only to record that the bytes differ while the public values are the same",
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The negative controls (Phase 6)
// ---------------------------------------------------------------------------------------------------------------

export interface NegativeControl {
  id: string;
  kind: "VERIFIER" | "VALIDATOR";
  description: string;
  expected: "REJECTED" | "REFUSED";
  /** For a validator-class control, the refusal (a chain link's id or a state) the mutation must produce. */
  expectedRefusal: string;
}

export const PA3D_NEGATIVE_CONTROLS: readonly NegativeControl[] = [
  {
    id: "NC-V1",
    kind: "VERIFIER",
    description: "the committed proof with one byte flipped, asked of the designated verifier on a development chain",
    expected: "REJECTED",
    expectedRefusal: "ProofInvalid",
  },
  {
    id: "NC-V2",
    kind: "VERIFIER",
    description: "the committed proof under a wrong program verifying key",
    expected: "REJECTED",
    expectedRefusal: "ProofInvalid",
  },
  {
    id: "NC-V3",
    kind: "VERIFIER",
    description: "the committed proof over wrong public values (the last bit flipped)",
    expected: "REJECTED",
    expectedRefusal: "ProofInvalid",
  },
  {
    id: "NC-V4",
    kind: "VERIFIER",
    description: "the committed proof truncated by its last byte",
    expected: "REJECTED",
    expectedRefusal: "revert",
  },
  {
    id: "NC-V5",
    kind: "VERIFIER",
    description: "the committed proof with its four-byte selector replaced",
    expected: "REJECTED",
    expectedRefusal: "revert",
  },
  {
    id: "NC-R1",
    kind: "VALIDATOR",
    description: "wrong input attribution: the run names another input digest",
    expected: "REFUSED",
    expectedRefusal: "INPUTS_TO_RUN",
  },
  {
    id: "NC-R2",
    kind: "VALIDATOR",
    description: "a stale proof under a modified manifest: the manifest's expected public values changed",
    expected: "REFUSED",
    expectedRefusal: "STATEMENT_TO_PUBLIC_VALUES",
  },
  {
    id: "NC-R3",
    kind: "VALIDATOR",
    description: "wrong proof digest: the verification names another proof digest",
    expected: "REFUSED",
    expectedRefusal: "PROOF_TO_VERIFICATION",
  },
  {
    id: "NC-R4",
    kind: "VALIDATOR",
    description: "malformed metadata: the run observation's schema is not v2",
    expected: "REFUSED",
    expectedRefusal: "SOURCE_TO_RUN",
  },
  {
    id: "NC-R5",
    kind: "VALIDATOR",
    description: "the run made from another source commit",
    expected: "REFUSED",
    expectedRefusal: "SOURCE_TO_RUN",
  },
  {
    id: "NC-R6",
    kind: "VALIDATOR",
    description: "the run watched by an observer other than the qualified one",
    expected: "REFUSED",
    expectedRefusal: "QUALIFICATION_TO_OBSERVER",
  },
  {
    id: "NC-R7",
    kind: "VALIDATOR",
    description: "the pre-proof attestation refused (a proof after a refusal)",
    expected: "REFUSED",
    expectedRefusal: "PA3D_PREPROOF_ENVIRONMENT_REFUSED",
  },
  {
    id: "NC-R8",
    kind: "VALIDATOR",
    description: "the designated verifier's acceptance edited to REJECTED",
    expected: "REFUSED",
    expectedRefusal: "PROOF_TO_VERIFICATION",
  },
  {
    id: "NC-R9",
    kind: "VALIDATOR",
    description: "the v2 record's egress assurance edited to an edge-probes-only one (continuous observation ABSENT)",
    expected: "REFUSED",
    expectedRefusal: "OBSERVATIONS_TO_RECORD",
  },
  {
    id: "NC-R12",
    kind: "VALIDATOR",
    description: "the v2 record's attribution residue edited to name an attempt of unknown outcome",
    expected: "REFUSED",
    expectedRefusal: "ATTRIBUTION_RESIDUE",
  },
  {
    id: "NC-R10",
    kind: "VALIDATOR",
    description: "the proof stamped before the manifest was authored",
    expected: "REFUSED",
    expectedRefusal: "MANIFEST_BEFORE_PROOF",
  },
  {
    id: "NC-R11",
    kind: "VALIDATOR",
    description: "the acquisition gate blocked in the manifest",
    expected: "REFUSED",
    expectedRefusal: "PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE",
  },
];

const MUTATIONS: Record<string, (i: Pa3dInputs) => void> = {
  "NC-R1": (i) => ((i.exercise as ExerciseView).run.inputsSha256 = "00".repeat(32)),
  "NC-R2": (i) => (i.manifest.value.statement.expectedPublicValues.sha256 = "00".repeat(32)),
  "NC-R3": (i) => ((i.exercise as ExerciseView).verification.proof.proofBytesSha256 = "00".repeat(32)),
  "NC-R4": (i) => ((i.exercise as ExerciseView).run.schema = "walletwall.sp1-proof-exercise-run.v1"),
  "NC-R5": (i) => ((i.exercise as ExerciseView).run.source.commit = "0".repeat(40)),
  "NC-R6": (i) => ((i.exercise as ExerciseView).run.observer.scriptSha256 = "00".repeat(32)),
  "NC-R7": (i) => {
    i.preproof.value.verdict = "PA3D_PREPROOF_ENVIRONMENT_REFUSED";
    i.preproof.value.refusals = ["HOST_BINARY_DIFFERS: the control's refusal"];
  },
  "NC-R8": (i) => ((i.exercise as ExerciseView).verification.acceptance = "REJECTED"),
  "NC-R9": (i) => {
    const a = (i.exercise as ExerciseView).record.assurance;
    a.level = "EDGE_PROBES_ONLY";
    a.continuousObservation = "ABSENT";
    a.processAttribution = "ABSENT";
    a.enforcement = "STATED";
    a.edgeProbes = "REFUSED_BEFORE_AND_AFTER";
  },
  "NC-R12": (i) => ((i.exercise as ExerciseView).record.assurance.unknownOutcomes = 1),
  "NC-R10": (i) => ((i.exercise as ExerciseView).run.timing.startedAtUtc = "2000-01-01T00:00:00Z"),
  "NC-R11": (i) => (i.manifest.value.acquisitionGate = { verdict: "BLOCKED", blockers: ["the control's blocker"] }),
};

export interface NegativeControlResult {
  id: string;
  kind: NegativeControl["kind"];
  expected: NegativeControl["expected"];
  expectedRefusal: string;
  outcome: "REFUSED" | "NOT_REFUSED" | "EXECUTED_BY_TEST_SUITE";
  /** The state the mutated evidence derives, then the id of every broken link; for a verifier control, the suite. */
  refusedBy: string[];
  refusal: string;
}

/**
 * Each validator-class control on a mutated copy of the inputs: REFUSED when the mutated evidence does not derive the
 * attributed-and-verified state and the expected refusal is, exactly, the state derived or the id of a broken link.
 */
export function runPa3dNegativeControls(inputs: Pa3dInputs): NegativeControlResult[] {
  if (inputs.exercise === null) throw new Error("the negative controls mutate an exercise: none is committed");
  return PA3D_NEGATIVE_CONTROLS.filter((c) => c.kind === "VALIDATOR").map((c) => {
    const copy: Pa3dInputs = JSON.parse(JSON.stringify(inputs));
    MUTATIONS[c.id](copy);
    const chain = chainOf(copy);
    const state = pa3dStateOf({
      gate: copy.manifest.value.acquisitionGate.verdict,
      preproof: copy.preproof.value.verdict,
      exercise: copy.exercise !== null,
      chainHolds: chain.holds,
    });
    const refusedBy = [state, ...chain.links.filter((l) => !l.holds).map((l) => l.id)];
    const refused = state !== "PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED" && refusedBy.includes(c.expectedRefusal);
    return {
      id: c.id,
      kind: c.kind,
      expected: c.expected,
      expectedRefusal: c.expectedRefusal,
      outcome: refused ? "REFUSED" : "NOT_REFUSED",
      refusedBy,
      refusal: [state, ...chain.blockers].join("; "),
    };
  });
}

// ---------------------------------------------------------------------------------------------------------------
// The state and the record
// ---------------------------------------------------------------------------------------------------------------

export function pa3dStateOf(facts: {
  gate: string;
  preproof: string;
  exercise: boolean;
  chainHolds: boolean;
}): FinalState {
  if (facts.gate !== "PASSED") return "PA3D_BLOCKED_ON_ARTIFACT_PROVENANCE";
  if (facts.preproof !== "PA3D_PREPROOF_ENVIRONMENT_VALID") return "PA3D_PREPROOF_ENVIRONMENT_REFUSED";
  if (!facts.exercise) return "PA3D_PROVING_FAILED";
  return facts.chainHolds ? "PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED" : "PA3D_PROOF_GENERATED_VERIFICATION_BLOCKED";
}

export interface Pa3dRecord {
  schema: typeof RECORD_SCHEMA;
  lane: typeof LANE;
  repository: string;
  productionSp1Binding: string;
  kind: string;
  state: FinalState;
  blockers: string[];
  next: { lane: string; what: string; started: false };
  source: Manifest["source"];
  manifest: { path: string; sha256: string; startedAtUtc: string };
  preproof: { path: string; sha256: string; verdict: string; measuredAtUtc: string };
  provenance: Provenance;
  exercise: {
    token: string;
    run: { path: string; sha256: string; measuredAtUtc: string; gateSeconds: number };
    verification: { path: string; sha256: string; acceptance: string; checks: number };
    record: { path: string; sha256: string; assurance: AssuranceView };
    proof: RunView["proof"];
  } | null;
  statement: Pick<Manifest["statement"], "designation" | "program" | "programVKey" | "guestElf" | "inputs"> & {
    expectedPublicValuesSha256: string;
  };
  chain: Chain;
  reproducibility: Reproducibility;
  negativeControls: NegativeControlResult[];
  derivedFrom: { path: string; sha256: string }[];
  establishes: string;
  doesNotEstablish: string;
}

export const RECORD_KEYS: readonly (keyof Pa3dRecord)[] = [
  "schema",
  "lane",
  "repository",
  "productionSp1Binding",
  "kind",
  "state",
  "blockers",
  "next",
  "source",
  "manifest",
  "preproof",
  "provenance",
  "exercise",
  "statement",
  "chain",
  "reproducibility",
  "negativeControls",
  "derivedFrom",
  "establishes",
  "doesNotEstablish",
];

export const ESTABLISHES =
  "one real Groth16 proof of the designated program was made from the manifest's source commit, on the manifest's host, by the committed attributed measurement under the qualified root observer and the complete egress boundary, from the archive-only circuit with the digest-pinned gnark image and the canonical host binary, on the committed inputs; it commits to the statement's public values; the designated verifier accepted it and refused its tampered copy on a development chain; the v2 record derives from the two observations with continuous observation and counted enforcement, its process attribution complete or partial as that record states, with no attempt to a resolver and none from the host namespace to beyond the VM of unseen outcome, and the residue the derivation does not judge (refused packets no attempt sent, sends of unseen destination, other-namespace sends beyond the VM) counted and named; the manifest stood in the checkout the attestation names and the attestation in the checkout the run names, each an ancestor of the checkout that validates; and every link from the source commit through the manifest, the attestation, the run, the proof, the verification and the record to the observer qualification compares equal committed digests";
export const DOES_NOT_ESTABLISH =
  "any production binding (PRODUCTION_SP1_BINDING = NOT_ESTABLISHED): no production verifier, Solidity, custody or policy semantics changed, no mainnet call was made; nor proof-byte determinism (one proof was authorized, Groth16 proving is randomized); nor complete process attribution where the v2 record states it partial; nor that nothing left the virtual machine by a path the inet boundary does not see (other namespaces' sends counted as residue left by vsock or a second runtime's network, and frames outside the inet family are not filtered by the table); nor more than the v2 record's own egress assurance states (the raw capture stays with the operator and is re-checkable only by someone given it); nor the soundness of the Groth16 trusted setup behind the key; nor that this environment proves within the rotation delay at another time";

/** The record from the committed inputs; refuses to be derived while no v2 exercise is committed. */
export function pa3dRecordFrom(inputs: Pa3dInputs): Pa3dRecord {
  if (inputs.exercise === null) {
    throw new Error(
      `NO_EXERCISE: no v2 exercise of ${inputs.manifest.value.source.commit} on ${inputs.manifest.value.environment.hostLabel} is committed; the record is written after the proof${inputs.exerciseErrors.length > 0 ? ` (${inputs.exerciseErrors.join("; ")})` : ""}`,
    );
  }
  const m = inputs.manifest.value;
  const chain = chainOf(inputs);
  const state = pa3dStateOf({
    gate: m.acquisitionGate.verdict,
    preproof: inputs.preproof.value.verdict,
    exercise: true,
    chainHolds: chain.holds,
  });
  const blockers = [
    ...(m.acquisitionGate.verdict === "PASSED" ? [] : m.acquisitionGate.blockers.map((b) => `ACQUISITION_GATE: ${b}`)),
    ...(inputs.preproof.value.verdict === "PA3D_PREPROOF_ENVIRONMENT_VALID"
      ? []
      : inputs.preproof.value.refusals.map((r) => `PREPROOF: ${r}`)),
    ...chain.blockers,
  ];
  const e = inputs.exercise;
  const derivedFrom = byPath([
    { path: inputs.manifest.path, sha256: inputs.manifest.sha256 },
    { path: inputs.preproof.path, sha256: inputs.preproof.sha256 },
    { path: inputs.qualification.path, sha256: inputs.qualification.sha256 },
    { path: e.run.path, sha256: e.run.sha256 },
    { path: e.verification.path, sha256: e.verification.sha256 },
    { path: e.record.path, sha256: e.record.sha256 },
  ]);
  return {
    schema: RECORD_SCHEMA,
    lane: LANE,
    repository: REPOSITORY_ID,
    productionSp1Binding: PRODUCTION_SP1_BINDING,
    kind: RECORD_KIND,
    state,
    blockers,
    next: { lane: NEXT_LANE, what: "design review", started: false },
    source: { ...m.source },
    manifest: { path: inputs.manifest.path, sha256: inputs.manifest.sha256, startedAtUtc: m.startedAtUtc },
    preproof: {
      path: inputs.preproof.path,
      sha256: inputs.preproof.sha256,
      verdict: inputs.preproof.value.verdict,
      measuredAtUtc: inputs.preproof.value.measuredAtUtc,
    },
    provenance: { ...inputs.provenance },
    exercise: {
      token: e.token,
      run: {
        path: e.run.path,
        sha256: e.run.sha256,
        measuredAtUtc: e.run.measuredAtUtc,
        gateSeconds: e.run.timing.gateSeconds,
      },
      verification: {
        path: e.verification.path,
        sha256: e.verification.sha256,
        acceptance: e.verification.acceptance,
        checks: e.verification.checks.length,
      },
      record: { path: e.record.path, sha256: e.record.sha256, assurance: { ...e.record.assurance } },
      proof: { ...e.run.proof },
    },
    statement: {
      designation: m.statement.designation,
      program: m.statement.program,
      programVKey: m.statement.programVKey,
      guestElf: { ...m.statement.guestElf },
      inputs: { ...m.statement.inputs },
      expectedPublicValuesSha256: m.statement.expectedPublicValues.sha256,
    },
    chain,
    reproducibility: reproducibilityOf(inputs),
    negativeControls: [
      ...PA3D_NEGATIVE_CONTROLS.filter((c) => c.kind === "VERIFIER").map((c): NegativeControlResult => ({
        id: c.id,
        kind: c.kind,
        expected: c.expected,
        expectedRefusal: c.expectedRefusal,
        outcome: "EXECUTED_BY_TEST_SUITE",
        refusedBy: [NEGATIVE_CONTROL_SUITE],
        refusal: `${NEGATIVE_CONTROL_SUITE} asks the designated verifier on a development chain (${c.description})`,
      })),
      ...runPa3dNegativeControls(inputs),
    ],
    derivedFrom,
    establishes: ESTABLISHES,
    doesNotEstablish: DOES_NOT_ESTABLISH,
  };
}

export const serializePa3dRecord = (r: Pa3dRecord) => serializeJson(r);

/** What is wrong with a committed record: its shape, its constants, and every leaf that differs from the derivation. */
export function pa3dRecordErrors(value: unknown, inputs: Pa3dInputs): string[] {
  if (!isObject(value)) return ["NOT_AN_OBJECT: a record is a JSON object"];
  const errors: string[] = [];
  const keys = new Set(Object.keys(value));
  for (const k of RECORD_KEYS) if (!keys.has(k)) errors.push(`MISSING_FIELD ${k}`);
  for (const k of keys) if (!(RECORD_KEYS as readonly string[]).includes(k)) errors.push(`UNKNOWN_FIELD ${k}`);
  if (value.schema !== RECORD_SCHEMA) errors.push(`SCHEMA: ${String(value.schema)} is not ${RECORD_SCHEMA}`);
  if (value.lane !== LANE) errors.push(`LANE: ${String(value.lane)} is not ${LANE}`);
  if (value.productionSp1Binding !== PRODUCTION_SP1_BINDING) {
    errors.push(`PRODUCTION_SP1_BINDING: ${String(value.productionSp1Binding)} is not ${PRODUCTION_SP1_BINDING}`);
  }
  if (!FINAL_STATES.includes(value.state)) errors.push(`STATE_UNKNOWN: ${String(value.state)}`);
  let derived: Pa3dRecord;
  try {
    derived = pa3dRecordFrom(inputs);
  } catch (error) {
    return [...errors, `DERIVATION_FAILED: ${(error as Error).message}`];
  }
  for (const d of leafDifferences(value, derived)) {
    errors.push(`LEAF_DIFFERS ${d.path}: committed ${JSON.stringify(d.a)}, derived ${JSON.stringify(d.b)}`);
  }
  return errors;
}

// ---------------------------------------------------------------------------------------------------------------
// The inputs from a checkout
// ---------------------------------------------------------------------------------------------------------------

function readText(repoRoot: string, rel: string): string | null {
  try {
    return lf(readFileSync(join(repoRoot, ...rel.split("/")), "utf8"));
  } catch {
    return null;
  }
}

/** Whether `commit` is an ancestor of the checkout and holds `rel` at exactly `sha` (LF bytes); null when not a commit here. */
function holdsAt(ctx: ManifestContext, commit: string | null, rel: string, sha: string): boolean | null {
  if (commit === null || !HEX40.test(commit) || ctx.parentsOf(commit) === null) return null;
  if (!ctx.isAncestorOfHead(commit)) return null;
  const blob = ctx.blobAt(commit, rel);
  return blob !== null && sha256(lf(blob.toString("utf8"))) === sha;
}

/**
 * The attempts the frozen leak rule does not judge, re-derived from the committed events by the frozen derivation
 * (observerEvidenceErrors): sends or connects inside the window from a namespace neither the host's nor the proof
 * container's, to a destination beyond the VM, that were SENT, CONNECTED or CLOSED_UNREFUSED. Null when the
 * derivation refuses the evidence (then the directory's own validator has refused the exercise too).
 */
export function otherNamespaceEgressOf(
  run: AttributedRunObservation,
  observerScriptSha256: string | null,
): number | null {
  const expectations: ObserverExpectations = {
    observerScriptSha256,
    mode: "RUN",
    probes: (["before", "after"] as const).flatMap((phase) =>
      run.egress[phase].map((p) => ({ phase, kind: p.kind as "dns" | "tcp", target: p.target })),
    ),
    gate: { startedAtUtc: run.timing.startedAtUtc, finishedAtUtc: run.timing.finishedAtUtc },
    run: { commit: run.source.commit, host: run.host },
  };
  const judged = observerEvidenceErrors(run.egress.observer, expectations);
  const a = judged.attribution;
  if (a === null || judged.refusals.length > 0 || a.window === null) return null;
  const { begin, end } = a.window;
  const hostNetns = run.egress.observer.host.netns;
  return a.attempts.filter(
    (x) =>
      !x.delegated &&
      x.i > begin &&
      x.i < end &&
      x.netns !== hostNetns &&
      x.scope !== "PROOF_CONTAINER" &&
      x.destClass === "EGRESS" &&
      (x.outcome === "SENT" || x.outcome === "CONNECTED" || x.outcome === "CLOSED_UNREFUSED"),
  ).length;
}

/**
 * The committed inputs of `repoRoot`: the manifest and the attestation each validated by its own validator, the
 * qualification as committed, SP1-PA3B's proof digest, the commit ancestry the evidence names, and the one v2
 * exercise (SP1-PA3D0's directory accepts the whole exercise directory or nothing) made from the manifest's source
 * commit on its host, projected into views.
 */
export function pa3dInputsFromRepo(repoRoot: string): Pa3dInputs {
  const ctx = manifestContextFromRepo(repoRoot);
  const manifestText = readText(repoRoot, MANIFEST_REL);
  if (manifestText === null) throw new Error(`${MANIFEST_REL} is missing`);
  const manifest = JSON.parse(manifestText) as Manifest;
  const manifestSha = sha256(manifestText);
  const preproofRel = preproofObservationRel(manifest.environment.hostLabel);
  const preproofText = readText(repoRoot, preproofRel);
  if (preproofText === null)
    throw new Error(`${preproofRel} is missing: the pre-proof attestation precedes the record`);
  const preproof = JSON.parse(preproofText) as PreproofObservation;
  const preproofSha = sha256(preproofText);
  const qualificationText = readText(repoRoot, QUALIFICATION_REL);
  if (qualificationText === null) throw new Error(`${QUALIFICATION_REL} is missing`);
  const qualification = JSON.parse(qualificationText);
  const pa3bText = readText(repoRoot, PA3B_RUN_REL);
  const pa3b = pa3bText === null ? null : (JSON.parse(pa3bText) as { proof?: { proofBytesSha256?: unknown } });

  const anchor = committedProductionAnchor(repoRoot);
  const archive = productionArchiveEvidenceOf(repoRoot);
  const evidence = productionExerciseEvidence(repoRoot, { anchor, archive });
  const exerciseErrors = [...evidence.errors];
  let exercise: ExerciseView | null = null;
  let runLaneCheckout: string | null = null;
  const candidates = evidence.accepted.filter((a) => {
    const run = readText(repoRoot, a.observations[0]);
    if (run === null) return false;
    const r = JSON.parse(run) as AttributedRunObservation;
    return (
      a.generation === "v2" && r.source?.commit === manifest.source.commit && r.host === manifest.environment.hostLabel
    );
  });
  if (candidates.length > 1)
    exerciseErrors.push(`${candidates.length} v2 exercises of the source commit are committed; one was authorized`);
  if (candidates.length === 1 && evidence.errors.length === 0) {
    const a = candidates[0];
    const runText = readText(repoRoot, a.observations[0]) as string;
    const verificationText = readText(repoRoot, a.observations[1]);
    const recordText = readText(repoRoot, a.path);
    if (verificationText === null || recordText === null) throw new Error(`${a.path}: an observation is missing`);
    const run = JSON.parse(runText) as AttributedRunObservation;
    const verification = JSON.parse(verificationText) as VerificationObservation;
    const record = JSON.parse(recordText) as AttributedProofExerciseRecord;
    const observerSha = exerciseExpectations(repoRoot, { anchor, archive }).scripts.observer ?? null;
    const events = record.egress.assurance.events;
    runLaneCheckout =
      run.platform.map((l) => /^laneCheckout=([0-9a-f]{40})(?:\s|$)/.exec(l)?.[1]).find((x) => x !== undefined) ?? null;
    exercise = {
      token: a.path.slice(a.path.lastIndexOf(".v2.") + 4, -".json".length),
      run: {
        path: a.observations[0],
        sha256: sha256(runText),
        schema: run.schema,
        host: run.host,
        measuredAtUtc: run.measuredAtUtc,
        source: { commit: run.source.commit, zkvmHostTree: run.source.zkvmHostTree },
        toolSha256: run.tool.scriptSha256,
        programVKey: run.anchor.programVKey,
        hostExecutableSha256: run.hostExecutable.sha256,
        inputsSha256: run.inputs.sha256,
        archiveRecordSha256: run.archiveRecord.sha256,
        installedMembers: run.installedCircuit.members.map((x) => ({ path: x.path, bytes: x.bytes, sha256: x.sha256 })),
        gnarkDigest: run.gnark.digest,
        proverMode: run.prover.mode,
        proof: {
          vkey: run.proof.vkey,
          selector: run.proof.selector,
          publicValues: run.proof.publicValues,
          publicValuesSha256: run.proof.publicValuesSha256,
          proofBytesSha256: run.proof.proofBytesSha256,
        },
        egress: {
          condition: run.egress.condition,
          probesRefused: [...run.egress.before, ...run.egress.after].every((p) => p.outcome === "REFUSED"),
          probes: run.egress.before.length + run.egress.after.length,
        },
        observer: {
          scriptSha256: run.egress.observer.tool.scriptSha256,
          mode: run.egress.observer.mode,
          boundary: boundaryOfSnapshots(run.egress.observer.boundary),
          bootId: run.egress.observer.bootId,
        },
        timing: {
          startedAtUtc: run.timing.startedAtUtc,
          finishedAtUtc: run.timing.finishedAtUtc,
          gateSeconds: run.timing.gateSeconds,
        },
      },
      verification: {
        path: a.observations[1],
        sha256: sha256(verificationText),
        runSha256: verification.run.sha256,
        acceptance: verification.acceptance,
        checks: verification.checks.map((c) => ({ real: c.verdicts.real, tampered: c.verdicts.tampered })),
        proof: {
          publicValuesSha256: verification.proof.publicValuesSha256,
          proofBytesSha256: verification.proof.proofBytesSha256,
        },
        verifierVersion: verification.verifier.version,
        runtimeCodeKeccak: verification.verifier.runtimeCodeKeccak,
      },
      record: {
        path: a.path,
        sha256: sha256(recordText),
        schema: record.schema,
        lane: record.lane,
        proof: { publicValuesSha256: record.proof.publicValuesSha256, proofBytesSha256: record.proof.proofBytesSha256 },
        assurance: {
          level: record.egress.assurance.level,
          continuousObservation: record.egress.assurance.continuousObservation,
          processAttribution: record.egress.assurance.processAttribution,
          enforcement: record.egress.assurance.enforcement,
          edgeProbes: record.egress.assurance.edgeProbes,
          attemptsInWindow: isCount(events?.attemptsInWindow) ? events.attemptsInWindow : null,
          refusedPackets: isCount(events?.refusedPackets) ? events.refusedPackets : null,
          unattributedEvents: isCount(record.egress.assurance.unattributedEvents)
            ? record.egress.assurance.unattributedEvents
            : null,
          unattributedOutsideWindow: isCount(events?.unattributedOutsideWindow)
            ? events.unattributedOutsideWindow
            : null,
          unknownOutcomes: isCount(events?.unknownOutcomes) ? events.unknownOutcomes : null,
          unseenDestinations: isCount(events?.unseenDestinations) ? events.unseenDestinations : null,
          otherNamespaceEgress: otherNamespaceEgressOf(run, observerSha),
        },
        derivedFrom: [...record.derivedFrom],
      },
    };
  }
  const laneCheckout = HEX40.test(String(preproof.laneCheckout?.commit)) ? preproof.laneCheckout.commit : null;
  return {
    manifest: { path: MANIFEST_REL, sha256: manifestSha, value: manifest, errors: manifestErrors(manifest, ctx) },
    preproof: { path: preproofRel, sha256: preproofSha, value: preproof, errors: preproofErrors(preproof, ctx) },
    qualification: {
      path: QUALIFICATION_REL,
      sha256: sha256(qualificationText),
      observerScriptSha256: String(qualification?.source?.observerScriptSha256),
      state: String(qualification?.state),
    },
    provenance: {
      laneCheckout,
      manifestInLaneCheckout: holdsAt(ctx, laneCheckout, MANIFEST_REL, manifestSha),
      runLaneCheckout,
      attestationInRunCheckout: holdsAt(ctx, runLaneCheckout, preproofRel, preproofSha),
    },
    pa3bProofBytesSha256: HEX64.test(String(pa3b?.proof?.proofBytesSha256))
      ? String(pa3b?.proof?.proofBytesSha256)
      : null,
    exercise,
    exerciseErrors,
  };
}

export { PREVIOUS_LANE };
