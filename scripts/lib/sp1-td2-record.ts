/**
 * SP1-TD2 implementation record (evidence/zk/sp1-td2/implementation-record.json): what TD2 built against the two
 * requirements SP1-TD1 froze, which test exercises each frozen proof, the TD1-N12 answer and the authorization cut.
 *
 * The record is checked against SP1-TD1's receipt, never against itself: the requirement ids, the proof lists, the
 * stop condition and the halt's scope must be TD1's exactly (TD2 builds what TD1 froze and re-decides nothing), the
 * TD1 receipt must be the bytes the record bound (TD2 does not rewrite it), every cited test file must exist and
 * name the proof it is cited for, the multisig vault's rotation can only be classified as new authority, and real
 * value stays blocked. The owner's decision on the multisig rotation (accepted, 2026-10-16) is held to the owner's
 * exact terms, and the scope it produces (SP1-TD1's, with the multisig vault admitted through its gate) is the one
 * the binding gate reads.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const TD2_RECORD_REL = "evidence/zk/sp1-td2/implementation-record.json";
export const TD2_RECORD_SCHEMA = "walletwall.sp1-td2-implementation-record.v1";
export const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
export const SP1_P1_SUPERSESSION_REL = "evidence/zk/sp1-p1/supersession.json";
const ENFORCEMENT = ["CODE", "PROCESS", "CODE_AND_PROCESS"];
const NEW_AUTHORITY = "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL";
/** The owner's decision on TD2-MULTISIG-ROTATION (2026-10-16), in the owner's terms. */
export const AUTHORIZATION_ACCEPTED = "ACCEPTED";
export const HALT_ADMISSION_ACCEPTED = "ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES";
export const ACCEPTED_EVALUATION = "NOT_FOUND_UNACCEPTABLE_BY_TD2_ACCEPTED_BY_THE_OWNER";
/** The frozen gates the owner's acceptance does not waive, as the owner listed them. */
export const NOT_WAIVED = [
  "TD1-N12",
  "designation",
  "code-hash",
  "registry",
  "per-chain execution",
  "successor identity",
];

export interface ScopeShape {
  applies: string[];
  excludedUntilRecoverable: { consumer: string; gate: string }[];
}

/**
 * The consumers a TD2 record admits to the halt's scope through a TD2 gate: the gate is built and tested, and the
 * owner accepted both its authorization cut and the admission. SP1-TD1 froze that a consumer it excluded "joins the
 * scope only through" its gate; nothing else admits one.
 */
export function admittedConsumers(record: unknown): { consumer: string; gate: string }[] {
  const requirements: any[] = Array.isArray((record as any)?.requirements) ? (record as any).requirements : [];
  return requirements
    .filter(
      (g) =>
        g?.status === "BUILT_AND_TESTED" &&
        typeof g.consumer === "string" &&
        g.haltAdmission === HALT_ADMISSION_ACCEPTED &&
        g.ownerDecision?.HALT_ADMISSION === HALT_ADMISSION_ACCEPTED &&
        g.ownerDecision?.TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION === AUTHORIZATION_ACCEPTED,
    )
    .map((g) => ({ consumer: g.consumer, gate: g.id }));
}

/** SP1-TD1's halt scope with each exclusion its gate admitted moved into the scope; every other exclusion stays. */
export function effectiveHaltScope<S extends ScopeShape>(scope: S, admitted: { consumer: string; gate: string }[]): S {
  const joins = (e: { consumer: string; gate: string }) =>
    admitted.some((a) => a.consumer === e.consumer && a.gate === e.gate);
  return {
    applies: [...scope.applies, ...scope.excludedUntilRecoverable.filter(joins).map((e) => e.consumer)].sort(),
    excludedUntilRecoverable: scope.excludedUntilRecoverable.filter((e) => !joins(e)).map((e) => ({ ...e })),
  } as S;
}

export interface Td2RecordContext {
  td1ReceiptBytes: Buffer;
  /** A repository file's text, or null when it does not exist. */
  readText: (rel: string) => string | null;
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** Every way the record departs from SP1-TD1's frozen requirements or from the repository; empty means valid. */
export function validateTd2Record(value: unknown, ctx: Td2RecordContext): string[] {
  const errors: string[] = [];
  const r = value as any;
  if (r === null || typeof r !== "object") return ["the record is not an object"];
  const td1 = JSON.parse(ctx.td1ReceiptBytes.toString("utf8"));
  const dc = td1.decisions.DEFECT_RESPONSE_COUPLING;

  if (r.schema !== TD2_RECORD_SCHEMA) errors.push(`schema must be ${TD2_RECORD_SCHEMA}`);
  if (r.lane !== "SP1-TD2") errors.push("lane must be SP1-TD2");
  if (r.verdict !== "BUILT_AND_TESTED_AWAITING_OWNER_REVIEW") errors.push("the verdict awaits the owner's review");
  if (r.td1Receipt?.path !== TD1_RECEIPT_REL) errors.push(`td1Receipt must be ${TD1_RECEIPT_REL}`);
  if (r.td1Receipt?.sha256 !== sha256(ctx.td1ReceiptBytes)) {
    errors.push("the SP1-TD1 receipt is not the bytes this record bound (TD2 never rewrites it)");
  }

  const frozen: any[] = dc.td2Requirements;
  const built: any[] = Array.isArray(r.requirements) ? r.requirements : [];
  if (
    !same(
      built.map((x) => x?.id),
      frozen.map((x) => x.id),
    )
  ) {
    errors.push(`requirements must be SP1-TD1's, in order: ${frozen.map((x) => x.id).join(", ")}`);
  }
  frozen.forEach((req, i) => {
    const b = built[i];
    if (b?.id !== req.id) return;
    if (b.status !== "BUILT_AND_TESTED") errors.push(`${req.id}: status must be BUILT_AND_TESTED`);
    const proofs: any[] = Array.isArray(b.proofs) ? b.proofs : [];
    if (
      !same(
        proofs.map((p) => p?.id),
        req.executableProofs,
      )
    ) {
      errors.push(`${req.id}: proofs must be SP1-TD1's executable proofs, in order`);
    }
    for (const p of proofs) {
      if (!ENFORCEMENT.includes(p?.enforcedBy))
        errors.push(`${req.id}/${String(p?.id)}: enforcedBy must be one of ${ENFORCEMENT.join(", ")}`);
      const tests: unknown[] = Array.isArray(p?.tests) ? p.tests : [];
      if (tests.length === 0) errors.push(`${req.id}/${String(p?.id)}: names no test`);
      for (const t of tests) {
        const text = typeof t === "string" && t.startsWith("test/") ? ctx.readText(t) : null;
        if (text === null) errors.push(`${req.id}/${String(p?.id)}: test file ${String(t)} does not exist`);
        else if (!text.includes(String(p.id)))
          errors.push(`${req.id}/${String(p?.id)}: ${String(t)} does not name the proof`);
      }
    }
  });

  const gate = built.find((b) => b?.id === "TD2-MULTISIG-ROTATION");
  const gateFrozen = frozen.find((x) => x.id === "TD2-MULTISIG-ROTATION");
  if (gate && gateFrozen) {
    if (!same(gate.stopCondition, gateFrozen.stopCondition))
      errors.push("TD2-MULTISIG-ROTATION: the stop condition must be SP1-TD1's, verbatim");
    // The owner's decision, closed on 2026-10-16: recorded exactly, never relabelled, waiving no frozen gate.
    const d = gate.ownerDecision ?? {};
    if (d.decidedBy !== "owner" || typeof d.date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(d.date)) {
      errors.push("TD2-MULTISIG-ROTATION: the owner's decision names who decided it and when");
    }
    if (d.TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION !== AUTHORIZATION_ACCEPTED) {
      errors.push(
        `TD2-MULTISIG-ROTATION: the owner decided TD2_MULTISIG_ROTATION_AUTHORIZATION_DECISION = ${AUTHORIZATION_ACCEPTED}`,
      );
    }
    if (d.MULTISIG_ROTATION_AUTHORITY_CLASS !== NEW_AUTHORITY) {
      errors.push(`TD2-MULTISIG-ROTATION: the accepted rotation stays ${NEW_AUTHORITY}, never authority-neutral`);
    }
    if (d.HALT_ADMISSION !== HALT_ADMISSION_ACCEPTED || gate.haltAdmission !== HALT_ADMISSION_ACCEPTED) {
      errors.push(`TD2-MULTISIG-ROTATION: the owner decided HALT_ADMISSION = ${HALT_ADMISSION_ACCEPTED}`);
    }
    if (!same(d.doesNotWaive, NOT_WAIVED)) {
      errors.push(`TD2-MULTISIG-ROTATION: the acceptance waives none of ${NOT_WAIVED.join(", ")}`);
    }
    if (!Array.isArray(d.reasoning) || d.reasoning.length === 0) {
      errors.push("TD2-MULTISIG-ROTATION: the owner's reasoning is recorded with the decision");
    }
    if (gate.stopConditionEvaluation !== ACCEPTED_EVALUATION) {
      errors.push(`TD2-MULTISIG-ROTATION: the stop condition's evaluation is ${ACCEPTED_EVALUATION}`);
    }
    const m = gate.measured ?? {};
    const inv = gateFrozen.invariants;
    if (!(typeof m.minimumDelaySeconds === "number" && m.minimumDelaySeconds >= inv.minimumDelaySeconds)) {
      errors.push(`TD2-MULTISIG-ROTATION: the delay must be at least ${inv.minimumDelaySeconds}s`);
    }
    for (const k of ["instantReplacement", "invokableByHaltPrincipal", "oldWrapperUnhalt"]) {
      if (m[k] !== inv[k]) errors.push(`TD2-MULTISIG-ROTATION: ${k} must be ${String(inv[k])}`);
    }
    if (!["CODE", "PROCESS", "CODE_AND_PROCESS"].includes(m.targetMustPassEvidenceGates)) {
      errors.push("TD2-MULTISIG-ROTATION: say how the evidence-gate requirement on the target is enforced");
    }
  }

  const n12 = r.td1N12 ?? {};
  if (typeof n12.answer !== "string" || !/^BY_(PROCESS|CODE)/.test(n12.answer))
    errors.push("td1N12: answer on chain or by process");
  for (const k of ["onChain", "byProcess", "notYetEnforced"]) {
    if (!Array.isArray(n12[k])) errors.push(`td1N12: ${k} must be a list`);
  }

  const cut: any[] = Array.isArray(r.authorizationCut) ? r.authorizationCut : [];
  const multisigRotation = cut.find(
    (c) =>
      c?.principal === "WALLETWALL_MULTISIG_VAULT_OWNER" &&
      Array.isArray(c.capabilities) &&
      c.capabilities.includes("PQ_VERIFIER_ROTATION"),
  );
  if (!multisigRotation) errors.push("authorizationCut: the multisig vault owner's rotation must be accounted");
  else if (multisigRotation.classification !== NEW_AUTHORITY || multisigRotation.widensAuthorization !== true) {
    errors.push(
      `authorizationCut: the multisig vault owner's rotation is ${NEW_AUTHORITY} and widens authorization, never authority-neutral`,
    );
  }
  const halt = cut.find((c) => c?.principal === "WALLETWALL_EMERGENCY_HALT_PRINCIPAL");
  if (!halt || !same(halt.capabilities, ["HALT"]) || halt.widensAuthorization !== false) {
    errors.push("authorizationCut: the halt principal holds HALT alone and widens nothing");
  }

  if (!same(r.haltScope, dc.haltDesign.haltScope)) errors.push("haltScope must be SP1-TD1's: TD2 changes no scope");
  if (!same(r.effectiveHaltScope, effectiveHaltScope(dc.haltDesign.haltScope, admittedConsumers(r)))) {
    errors.push("effectiveHaltScope must be SP1-TD1's scope with exactly the owner's admissions applied");
  }
  if (r.realValue?.blocked !== true || !Array.isArray(r.realValue?.blockers) || r.realValue.blockers.length === 0) {
    errors.push("real value stays blocked, with its blockers named");
  }

  const supersession = ctx.readText(SP1_P1_SUPERSESSION_REL);
  const names =
    supersession !== null && JSON.parse(supersession).supersededBy?.some((s: any) => s?.record === TD2_RECORD_REL);
  if (
    !same(r.supersedes, [
      { record: "evidence/zk/sp1-p1/stop-receipt.json", via: SP1_P1_SUPERSESSION_REL, finding: "TD1-N4" },
    ]) ||
    !names
  ) {
    errors.push("the SP1-P1 STOP receipt is superseded through its supersession record, which names this record");
  }
  return errors;
}

/** The committed record, validated against the repository. */
export function validateCommittedTd2Record(repoRoot = "."): string[] {
  const readText = (rel: string) =>
    existsSync(resolve(repoRoot, rel)) ? readFileSync(resolve(repoRoot, rel), "utf8") : null;
  const record = JSON.parse(readFileSync(resolve(repoRoot, TD2_RECORD_REL), "utf8")) as unknown;
  return validateTd2Record(record, { td1ReceiptBytes: readFileSync(resolve(repoRoot, TD1_RECEIPT_REL)), readText });
}
