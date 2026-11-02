/**
 * SP1-PA3E — the production-binding design manifest and its validator.
 *
 * PA3D made one real v2 proof and ended with PRODUCTION_SP1_BINDING = NOT_ESTABLISHED. PA3E is the design lane that
 * follows: it writes down, before any implementation, what statement WalletWall would have to bind, through which
 * components, under which trust assumptions, for a valid SP1 proof to influence Vault behaviour. The manifest at
 * {@link DESIGN_REL} is that design in machine-readable form; {@link DESIGN_DOC_REL} is its prose. Neither is a
 * measurement and neither changes a contract: the validator checks the design for internal consistency (every threat
 * bound or marked open, a contiguous fixed-width public-values layout, a lifecycle with no way back from REVOKED, a
 * recommendation the matrix does not block, fail-closed failures, every PA3D residue adjudicated) and checks that the
 * document states every identifier the manifest declares, together with the lane's final state and the binding
 * status, which this lane can never raise. Research prototype. Not audited. Testnet/local only. No real funds.
 */

export const LANE = "SP1-PA3E";
export const DESIGN_SCHEMA = "walletwall.sp1-production-binding-design.v1";
export const DESIGN_REL = "evidence/zk/sp1-impl/pa3e-production-binding-design.json";
export const DESIGN_JSON_SCHEMA_REL = "evidence/zk/schema/sp1-production-binding-design.v1.schema.json";
export const DESIGN_DOC_REL = "docs/SP1_Production_Binding_Design.md";

/** The lane's three terminal states, the spec's list in the spec's order. */
export const FINAL_STATES = [
  "PA3E_PRODUCTION_BINDING_DESIGN_READY",
  "PA3E_DESIGN_BLOCKED",
  "PA3E_BLOCKED_ON_PA3D_MERGE",
] as const;
export type FinalState = (typeof FINAL_STATES)[number];

/** The one value this lane may ever write for the binding status. */
export const PRODUCTION_SP1_BINDING = "NOT_ESTABLISHED" as const;

/** The twenty threats the spec names, in the spec's order; the manifest must analyse exactly these. */
export const REQUIRED_THREATS = [
  "T01", // proof replay
  "T02", // cross-chain replay
  "T03", // cross-Vault replay
  "T04", // cross-user replay
  "T05", // cross-operation replay
  "T06", // stale policy replay
  "T07", // stale state replay
  "T08", // altered destination
  "T09", // altered amount
  "T10", // altered asset
  "T11", // verifier/program substitution
  "T12", // old-program downgrade
  "T13", // a proof made for development infrastructure reused in production
  "T14", // a valid proof paired with wrong public values
  "T15", // a proof made under a different policy version
  "T16", // stale or forked chain data
  "T17", // source-commit substitution
  "T18", // malformed encoding ambiguity
  "T19", // canonicalization differences
  "T20", // verifier upgrade ambiguity
] as const;
export type ThreatId = (typeof REQUIRED_THREATS)[number];

/** The PA3D residues the spec requires adjudicated; the manifest may add more, never fewer. */
export const REQUIRED_RESIDUES = [
  "PA3D-F1",
  "PA3D-F4",
  "PA3D-ATTRIBUTION-PARTIAL",
  "PA3D-CHRONYD",
  "PA3D-ACQUISITION-NODE-TREE",
  "PA3D-VALIDATORS-NOT-IN-CI",
] as const;

export const THREAT_STATUSES = ["RESOLVED", "PARTIAL", "UNRESOLVED"] as const;
export const CLASSIFICATIONS = ["MUST_BIND", "MAY_BIND", "MUST_NOT_BIND", "NOT_APPLICABLE"] as const;
export const BOUND_BY = [
  "JOURNAL_WORD",
  "EIP712_DIGEST",
  "VERIFIER_IMMUTABLE",
  "PROOF_SELECTOR_AND_CODEHASH_PIN",
  "CONSUMER_STORAGE",
  "NONE",
] as const;
export const SCORES = ["STRONG", "ACCEPTABLE", "WEAK", "BLOCKING"] as const;
export const VERDICTS = ["RECOMMENDED", "VIABLE", "REJECTED"] as const;
export const DISPOSITIONS = [
  "MUST_FIX_BEFORE_IMPLEMENTATION",
  "MUST_FIX_BEFORE_PRODUCTION",
  "ACCEPTABLE_WITH_DOCUMENTED_BOUNDARY",
  "IRRELEVANT_TO_PRODUCTION_BINDING",
] as const;
export const OUTCOMES = ["REVERT", "DENY_FALSE", "NO_STATE_CHANGE"] as const;
export const GATE_PLACES = [
  "UNIT",
  "INTEGRATION",
  "SOLIDITY",
  "HOST_QUALIFICATION",
  "RELEASE_EVIDENCE",
  "CANONICAL_CI",
] as const;
export const GATE_STATUSES = ["EXISTS", "PARTIAL", "MISSING"] as const;
export const TIERS = ["T0", "T1", "T2", "T3"] as const;
export const LIFECYCLE_STATES = ["PROPOSED", "QUALIFIED", "ACTIVE", "DEPRECATED", "REVOKED"] as const;
export const TRUST_LAYERS = ["A", "B", "C", "D", "E", "F", "G"] as const;

/** The seventeen sections the design document must carry, in the spec's order; matched as `## <n>. <title>`. */
export const REQUIRED_SECTIONS = [
  "Evidence baseline",
  "Production statement",
  "Trust layers",
  "Threat model",
  "Candidate architectures",
  "Decision matrix",
  "Recommended architecture",
  "Public-values contract",
  "Replay model",
  "Verifier and program lifecycle",
  "PA3D residue disposition",
  "CI and release gates",
  "Failure semantics",
  "Security invariants",
  "Unresolved questions",
  "Non-goals",
  "Implementation-lane prerequisites",
] as const;

export interface PublicInput {
  name: string;
  classification: (typeof CLASSIFICATIONS)[number];
  boundBy: (typeof BOUND_BY)[number];
  today: string;
  why: string;
}

export interface Threat {
  id: ThreatId;
  name: string;
  status: (typeof THREAT_STATUSES)[number];
  layers: string[];
  binding: string;
  residual: string;
}

export interface Candidate {
  id: string;
  name: string;
  summary: string;
  verdict: (typeof VERDICTS)[number];
  analysis: Record<string, string>;
}

export interface LifecycleState {
  id: string;
  meaning: string;
  mayProve: boolean;
  mayVerify: boolean;
  mayAuthorizeNew: boolean;
  mayAuthorizeExisting: boolean;
  historicalProofsAuditable: boolean;
  proofBeforeTransitionExecutesAfter: string;
}

export interface LifecycleTransition {
  from: string;
  to: string;
  by: string;
  evidence: string;
  delaySeconds?: number;
}

export interface Residue {
  id: string;
  name: string;
  finding: string;
  disposition: (typeof DISPOSITIONS)[number];
  why: string;
  boundary: string;
}

export interface Gate {
  id: string;
  name: string;
  where: (typeof GATE_PLACES)[number][];
  status: (typeof GATE_STATUSES)[number];
  reference: string;
}

export interface Failure {
  failure: string;
  outcome: (typeof OUTCOMES)[number];
  where: string;
  detail: string;
}

export interface Invariant {
  id: string;
  statement: string;
  tier: (typeof TIERS)[number];
  closes: ThreatId[];
  enforcedToday: string;
}

export interface Unresolved {
  id: string;
  question: string;
  blocking: boolean;
  owner: string;
}

export interface DesignManifest {
  schema: string;
  lane: string;
  repository: string;
  kind: string;
  state: FinalState;
  productionSp1Binding: typeof PRODUCTION_SP1_BINDING;
  evidenceBaseline: {
    mainCommit: string;
    mergeCommit: { sha: string; parents: string[]; pullRequest: number; mergedAtUtc: string };
    version: string;
    pa3dRecord: { path: string; sha256: string; state: string };
    program: {
      designation: string;
      program: string;
      programVKey: string;
      guestElfSha256: string;
      sp1Version: string;
      circuitVersion: string;
      sp1VerifierCodehash: string;
    };
    proof: {
      token: string;
      publicValuesSha256: string;
      proofBytesSha256: string;
      selector: string;
      verification: string;
      proofByteDeterminism: string;
    };
    qualification: { path: string; verdict: string };
    residue: {
      unattributedEvents: number;
      unseenDestinations: number;
      otherNamespaceEgress: number;
      unknownOutcomes: number;
    };
    carriedForward: string[];
  };
  statement: {
    subject: string;
    relation: string;
    consumerPath: string[];
    publicInputs: PublicInput[];
    privateInputs: { name: string; why: string }[];
    verificationMeans: string[];
    verificationDoesNotMean: string[];
  };
  trustLayers: { id: string; name: string; question: string; establishedBy: string; transition: string }[];
  trustAssumptions: string[];
  threats: Threat[];
  candidates: Candidate[];
  decisionMatrix: { dimensions: string[]; scores: Record<string, Record<string, (typeof SCORES)[number]>> };
  recommended: { candidate: string; why: string; rejected: { candidate: string; why: string }[] };
  identity: {
    programIdentity: string;
    verifierIdentity: string;
    consumerIdentity: string;
    whoMayAdd: string;
    whoMayRemove: string;
    emergencyRevoke: string;
    downgrade: string;
    oldProofsAfterUpgrade: string;
    evidencePerChange: string[];
  };
  encoding: {
    publicValues: {
      totalBytes: number;
      layout: string;
      fields: { name: string; abiType: string; offset: number; bytes: number; semantics: string; checkedBy: string }[];
    };
    digest: { scheme: string; domain: string; typeHashes: string[]; construction: string };
    proofPayload: { abi: string; selector: string };
    verifierBinding: { programVKey: string; publicValuesDigest: string };
    domainSeparation: string[];
    forbidden: string[];
    nextGeneration: string;
  };
  replay: {
    nullifier: string;
    stateLocation: string;
    consumedWhen: string;
    atomicity: string;
    onRevert: string;
    retry: string;
    crossChain: string;
    crossContract: string;
    crossUser: string;
    deadline: string;
    notBound: string[];
  };
  lifecycle: {
    mapping: string;
    states: LifecycleState[];
    transitions: LifecycleTransition[];
  };
  residues: Residue[];
  gates: Gate[];
  failures: Failure[];
  invariants: Invariant[];
  unresolved: Unresolved[];
  nonGoals: string[];
  implementationPrerequisites: string[];
}

const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const nonEmpty = (x: unknown, min = 1): x is string => typeof x === "string" && x.trim().length >= min;

/**
 * Every way the design manifest can be inconsistent with itself or with the spec, as `CODE detail` strings; empty
 * for a consistent manifest. Pure: reads nothing but its argument.
 */
export function designErrors(input: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(input)) return ["NOT_AN_OBJECT"];
  const m = input as unknown as DesignManifest;

  if (m.schema !== DESIGN_SCHEMA) errors.push(`SCHEMA ${String(m.schema)}`);
  if (m.lane !== LANE) errors.push(`LANE ${String(m.lane)}`);
  if (!(FINAL_STATES as readonly string[]).includes(m.state)) errors.push(`STATE_UNKNOWN ${String(m.state)}`);
  if (m.productionSp1Binding !== PRODUCTION_SP1_BINDING) {
    errors.push(`PRODUCTION_SP1_BINDING ${String(m.productionSp1Binding)}: this lane can only write NOT_ESTABLISHED`);
  }

  // Evidence baseline: the merge commit is main, and every carried-forward fact is stated.
  const b = m.evidenceBaseline;
  if (!isRecord(b)) errors.push("BASELINE_MISSING");
  else {
    if (!/^[0-9a-f]{40}$/.test(String(b.mainCommit))) errors.push("BASELINE_MAIN_COMMIT");
    if (!isRecord(b.mergeCommit) || b.mergeCommit.sha !== b.mainCommit) errors.push("BASELINE_MERGE_IS_MAIN");
    if (!isRecord(b.mergeCommit) || !Array.isArray(b.mergeCommit.parents) || b.mergeCommit.parents.length !== 2) {
      errors.push("BASELINE_MERGE_PARENTS");
    }
    if (!isRecord(b.pa3dRecord) || b.pa3dRecord.state !== "PA3D_V2_PROOF_ATTRIBUTED_AND_VERIFIED") {
      errors.push("BASELINE_PA3D_STATE");
    }
    if (!isRecord(b.proof) || b.proof.proofByteDeterminism !== "NOT_CLAIMED")
      errors.push("BASELINE_DETERMINISM_CLAIMED");
    if (!Array.isArray(b.carriedForward) || b.carriedForward.length < 12) errors.push("BASELINE_CARRIED_FORWARD");
  }

  // Statement: every public input classified with a reason.
  const s = m.statement;
  if (!isRecord(s) || !Array.isArray(s.publicInputs) || s.publicInputs.length === 0) errors.push("STATEMENT_MISSING");
  else {
    for (const p of s.publicInputs) {
      if (!(CLASSIFICATIONS as readonly string[]).includes(p.classification)) {
        errors.push(`PUBLIC_INPUT_CLASSIFICATION ${p.name}`);
      }
      if (!(BOUND_BY as readonly string[]).includes(p.boundBy)) errors.push(`PUBLIC_INPUT_BOUND_BY ${p.name}`);
      if (p.classification === "MUST_BIND" && p.boundBy === "NONE")
        errors.push(`PUBLIC_INPUT_MUST_BIND_UNBOUND ${p.name}`);
      if (!nonEmpty(p.why, 20)) errors.push(`PUBLIC_INPUT_REASON_MISSING ${p.name}`);
    }
    if (!Array.isArray(s.verificationMeans) || s.verificationMeans.length === 0) errors.push("STATEMENT_MEANS");
    if (!Array.isArray(s.verificationDoesNotMean) || s.verificationDoesNotMean.length === 0)
      errors.push("STATEMENT_DOES_NOT_MEAN");
  }

  // Trust layers A..G, in order, each with its transition.
  if (!Array.isArray(m.trustLayers) || m.trustLayers.map((l) => l.id).join("") !== TRUST_LAYERS.join("")) {
    errors.push("TRUST_LAYERS A..G in order");
  } else {
    for (const l of m.trustLayers) if (!nonEmpty(l.transition, 10)) errors.push(`TRUST_LAYER_TRANSITION ${l.id}`);
  }

  // Threats: exactly the spec's twenty, each bound or honestly open.
  if (!Array.isArray(m.threats) || m.threats.map((t) => t.id).join(",") !== REQUIRED_THREATS.join(",")) {
    errors.push("THREATS_LIST exactly T01..T20 in order");
  } else {
    for (const t of m.threats) {
      if (!(THREAT_STATUSES as readonly string[]).includes(t.status)) errors.push(`THREAT_STATUS ${t.id}`);
      if (t.status === "RESOLVED" && !nonEmpty(t.binding, 10)) errors.push(`THREAT_UNBOUND ${t.id}`);
      if (t.status !== "RESOLVED" && !nonEmpty(t.residual, 10)) errors.push(`THREAT_RESIDUAL_MISSING ${t.id}`);
      if (!Array.isArray(t.layers) || t.layers.some((l) => !(TRUST_LAYERS as readonly string[]).includes(l))) {
        errors.push(`THREAT_LAYERS ${t.id}`);
      }
    }
  }

  // Candidates and the matrix: at least A, B, C; every candidate scored on every dimension; the recommendation is a
  // candidate the matrix does not block.
  const ids = Array.isArray(m.candidates) ? m.candidates.map((c) => c.id) : [];
  if (!["A", "B", "C"].every((id) => ids.includes(id))) errors.push("CANDIDATES_MINIMUM A, B and C");
  for (const c of m.candidates ?? []) {
    if (!(VERDICTS as readonly string[]).includes(c.verdict)) errors.push(`CANDIDATE_VERDICT ${c.id}`);
  }
  const dm = m.decisionMatrix;
  if (!isRecord(dm) || !Array.isArray(dm.dimensions) || !isRecord(dm.scores)) errors.push("MATRIX_MISSING");
  else {
    for (const id of ids) {
      const row = dm.scores[id];
      if (!isRecord(row)) {
        errors.push(`MATRIX_INCOMPLETE ${id}`);
        continue;
      }
      for (const d of dm.dimensions) {
        if (!(d in row)) errors.push(`MATRIX_INCOMPLETE ${id}.${d}`);
        else if (!(SCORES as readonly string[]).includes(row[d]))
          errors.push(`MATRIX_SCORE ${id}.${d}=${String(row[d])}`);
      }
    }
    const rec = m.recommended?.candidate;
    if (!ids.includes(rec)) errors.push(`RECOMMENDED_UNKNOWN ${String(rec)}`);
    else {
      const row = dm.scores[rec] ?? {};
      const blocked = Object.entries(row).filter(([, v]) => v === "BLOCKING");
      if (blocked.length > 0) errors.push(`RECOMMENDED_BLOCKED ${rec} on ${blocked.map(([d]) => d).join(", ")}`);
      const cand = m.candidates.find((c) => c.id === rec);
      if (cand && cand.verdict !== "RECOMMENDED") errors.push(`RECOMMENDED_VERDICT ${rec} is ${cand.verdict}`);
    }
    for (const c of m.candidates ?? []) {
      if (c.verdict === "RECOMMENDED" && c.id !== rec) errors.push(`RECOMMENDED_TWICE ${c.id}`);
    }
  }

  // Encoding: a contiguous layout of 32-byte words summing to the stated length.
  const pv = m.encoding?.publicValues;
  if (!isRecord(pv) || !Array.isArray(pv.fields)) errors.push("ENCODING_MISSING");
  else {
    let expectOffset = 0;
    let sum = 0;
    for (const f of pv.fields) {
      if (f.offset !== expectOffset) errors.push(`ENCODING_GAP ${f.name} at ${f.offset}, expected ${expectOffset}`);
      if (f.bytes !== 32) errors.push(`ENCODING_WORD ${f.name} is ${f.bytes} bytes, static ABI words are 32`);
      expectOffset = f.offset + f.bytes;
      sum += f.bytes;
    }
    if (sum !== pv.totalBytes) errors.push(`ENCODING_LENGTH fields sum to ${sum}, totalBytes says ${pv.totalBytes}`);
    if (!nonEmpty(m.encoding.verifierBinding?.publicValuesDigest, 10)) errors.push("ENCODING_PUBLIC_VALUES_DIGEST");
    if (!Array.isArray(m.encoding.forbidden) || m.encoding.forbidden.length === 0) errors.push("ENCODING_FORBIDDEN");
  }

  // Lifecycle: the five states, no power at REVOKED, nothing leads back from it, every transition between known states.
  const lc = m.lifecycle;
  if (!isRecord(lc) || !Array.isArray(lc.states) || !Array.isArray(lc.transitions)) errors.push("LIFECYCLE_MISSING");
  else {
    const stateIds = lc.states.map((st) => st.id);
    for (const required of LIFECYCLE_STATES)
      if (!stateIds.includes(required)) errors.push(`LIFECYCLE_STATE_MISSING ${required}`);
    const revoked = lc.states.find((st) => st.id === "REVOKED");
    if (revoked && (revoked.mayVerify || revoked.mayAuthorizeNew || revoked.mayAuthorizeExisting)) {
      errors.push("LIFECYCLE_REVOKED_POWER: REVOKED verifies or authorizes nothing");
    }
    for (const st of lc.states) {
      if (st.id !== "ACTIVE" && st.mayAuthorizeNew) errors.push(`LIFECYCLE_AUTHORIZES_OUTSIDE_ACTIVE ${st.id}`);
      if (!st.historicalProofsAuditable)
        errors.push(`LIFECYCLE_AUDITABILITY ${st.id}: history stays auditable in every state`);
    }
    for (const t of lc.transitions) {
      if (!stateIds.includes(t.from)) errors.push(`LIFECYCLE_UNKNOWN_STATE ${t.from}`);
      if (!stateIds.includes(t.to)) errors.push(`LIFECYCLE_UNKNOWN_STATE ${t.to}`);
      if (t.from === "REVOKED") errors.push(`LIFECYCLE_REVOKED_EXIT ${t.from}->${t.to}`);
      if (t.from === "DEPRECATED" && t.to === "ACTIVE") errors.push("LIFECYCLE_DOWNGRADE DEPRECATED->ACTIVE");
      if (!nonEmpty(t.evidence, 10)) errors.push(`LIFECYCLE_EVIDENCE ${t.from}->${t.to}`);
    }
  }

  // Residues: every required one present, each in one of the four classes with a reason.
  const residueIds = Array.isArray(m.residues) ? m.residues.map((r) => r.id) : [];
  for (const required of REQUIRED_RESIDUES)
    if (!residueIds.includes(required)) errors.push(`RESIDUE_MISSING ${required}`);
  for (const r of m.residues ?? []) {
    if (!(DISPOSITIONS as readonly string[]).includes(r.disposition)) errors.push(`RESIDUE_DISPOSITION ${r.id}`);
    if (!nonEmpty(r.why, 20)) errors.push(`RESIDUE_REASON ${r.id}`);
  }

  // Gates: a place and a status each.
  for (const g of m.gates ?? []) {
    if (
      !Array.isArray(g.where) ||
      g.where.length === 0 ||
      g.where.some((w) => !(GATE_PLACES as readonly string[]).includes(w))
    ) {
      errors.push(`GATE_WHERE ${g.id}`);
    }
    if (!(GATE_STATUSES as readonly string[]).includes(g.status)) errors.push(`GATE_STATUS ${g.id}`);
  }
  if (!Array.isArray(m.gates) || m.gates.length === 0) errors.push("GATES_MISSING");

  // Failures: every one fails closed.
  if (!Array.isArray(m.failures) || m.failures.length === 0) errors.push("FAILURES_MISSING");
  for (const f of m.failures ?? []) {
    if (!(OUTCOMES as readonly string[]).includes(f.outcome))
      errors.push(`FAILURE_NOT_CLOSED ${f.failure}: ${String(f.outcome)}`);
  }

  // Invariants: PB-1..PB-10 at least, a tier each, closing only known threats.
  const invIds = Array.isArray(m.invariants) ? m.invariants.map((i) => i.id) : [];
  for (let n = 1; n <= 10; n++) if (!invIds.includes(`PB-${n}`)) errors.push(`INVARIANT_MISSING PB-${n}`);
  for (const i of m.invariants ?? []) {
    if (!(TIERS as readonly string[]).includes(i.tier)) errors.push(`INVARIANT_TIER ${i.id}`);
    for (const t of i.closes ?? []) {
      if (!(REQUIRED_THREATS as readonly string[]).includes(t))
        errors.push(`INVARIANT_UNKNOWN_THREAT ${i.id} closes ${t}`);
    }
    if (!nonEmpty(i.statement, 20)) errors.push(`INVARIANT_STATEMENT ${i.id}`);
  }

  // The ready state admits no blocking question.
  const blocking = (m.unresolved ?? []).filter((u) => u.blocking);
  if (m.state === "PA3E_PRODUCTION_BINDING_DESIGN_READY" && blocking.length > 0) {
    errors.push(`READY_WITH_BLOCKING_QUESTION ${blocking.map((u) => u.id).join(", ")}`);
  }
  if (m.state === "PA3E_DESIGN_BLOCKED" && blocking.length === 0) errors.push("BLOCKED_WITHOUT_BLOCKING_QUESTION");
  if (!Array.isArray(m.nonGoals) || m.nonGoals.length === 0) errors.push("NON_GOALS_MISSING");
  if (!Array.isArray(m.implementationPrerequisites) || m.implementationPrerequisites.length === 0) {
    errors.push("PREREQUISITES_MISSING");
  }
  return errors;
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Every way the design document fails to state what the manifest declares: a missing required section, a missing
 * threat, invariant, residue, candidate, gate or lifecycle-state identifier, a missing baseline commit, a state line
 * other than the manifest's, a binding line other than NOT_ESTABLISHED, a missing disclaimer, or the forbidden claim
 * that PA3D was fully hermetic.
 */
export function designDocErrors(m: DesignManifest, text: string): string[] {
  const errors: string[] = [];
  const doc = text.replace(/\r\n/g, "\n");
  REQUIRED_SECTIONS.forEach((title, i) => {
    const re = new RegExp(`^## ${i + 1}\\. ${escapeRegExp(title)}\\b`, "mi");
    if (!re.test(doc)) errors.push(`DOC_SECTION ${i + 1}. ${title}`);
  });
  const ids = [
    ...m.threats.map((t) => t.id),
    ...m.invariants.map((i) => i.id),
    ...m.residues.map((r) => r.id),
    ...m.gates.map((g) => g.id),
    ...m.unresolved.map((u) => u.id),
    ...m.lifecycle.states.map((s) => s.id),
    ...m.trustLayers.map((l) => `Layer ${l.id}`),
  ];
  for (const id of ids) if (!doc.includes(id)) errors.push(`DOC_MISSING ${id}`);
  for (const c of m.candidates) if (!doc.includes(`Candidate ${c.id}`)) errors.push(`DOC_MISSING Candidate ${c.id}`);
  if (!doc.includes(m.evidenceBaseline.mainCommit)) errors.push("DOC_BASELINE main commit");
  if (!doc.includes(`State: \`${m.state}\``)) errors.push(`DOC_STATE State: \`${m.state}\``);
  if (!doc.includes(`PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING}`)) errors.push("DOC_BINDING");
  if (/PRODUCTION_SP1_BINDING = (?!NOT_ESTABLISHED)/.test(doc)) errors.push("DOC_BINDING another value is stated");
  if (!/research prototype/i.test(doc) || !/not audited/i.test(doc)) errors.push("DOC_DISCLAIMER");
  if (/fully hermetic/i.test(doc)) errors.push("DOC_HERMETIC: PA3D may not be called fully hermetic");
  return errors;
}
