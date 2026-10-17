/**
 * The zkvm/host RustSec advisory record (scripts/lib/sp1-host-advisories.ts; docs/SP1_Host_Lockfile_Advisories.md).
 *
 * The committed record must be exactly what designation d1's zkvm/host subject, the committed observation and the
 * reviewed claims derive, and the check must give two verdicts that never stand in for each other: ASSESSMENT_VALID
 * (what was assessed and why still holds) and the dependency status (NOT_DEPENDENCY_SAFE while any RustSec
 * vulnerability or unsoundness is locked). Each adversarial case below changes one input and asserts the specific
 * issue that refuses it; where an outer check would also refuse, a self-consistent variant (the record regenerated
 * from the tampered inputs) shows that the inner layer refuses on its own.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  ADVISORIES_DOC_REL,
  ASSUMPTIONS,
  CARGO_AUDIT_VERSION,
  CLAIMS,
  HOST_ADVISORIES_REL,
  LOCKFILES,
  OWNER_DECISION,
  SOURCE_FACTS,
  advisoryStateFromRepo,
  auditFindingsOf,
  bucketOf,
  catalogIssues,
  compareVersions,
  countMatches,
  dependencyStatusOf,
  deriveHostAdvisoryRecord,
  deriveRecordWith,
  directDependents,
  evaluateHostAdvisories,
  evidenceResults,
  featuresOf,
  fixFactsOf,
  hostAdvisoryVerdict,
  indexEntriesOf,
  memberSelected,
  minimalPatchedVersion,
  normalizeCargoOutput,
  parseCargoLock,
  parseSimpleManifest,
  preciseProbeCommand,
  preciseProbeOf,
  satisfies,
  serializeHostAdvisoryRecord,
  sourceFactResult,
  sparseIndexPath,
  stripRustComments,
  treeCommand,
  treeFactsOf,
  updateChangesOf,
  updateProbeOf,
  yankedPackages,
  type AdvisoryState,
  type Claim,
  type FixFacts,
  type MeasuredFinding,
  type Verdict,
} from "../scripts/lib/sp1-host-advisories";

const sha256 = (b: string) => createHash("sha256").update(b).digest("hex");
const R0285 = "RUSTSEC-2026-0285 rustls@0.23.40";
const R0346 = "RUSTSEC-2026-0346 rustls@0.23.40";
const R0348 = "RUSTSEC-2026-0348 rustls@0.23.40";
const H2 = "RUSTSEC-2026-0258 h2@0.4.14";

let REPO: AdvisoryState;
const fresh = (): AdvisoryState => structuredClone(REPO);
const codes = (v: Verdict) => [...new Set(v.issues.map((i) => i.code))].sort();
const messages = (v: Verdict, code: string) =>
  v.issues
    .filter((i) => i.code === code)
    .map((i) => i.message)
    .join("\n");
const recordOf = (s: AdvisoryState) => JSON.parse(s.recordText as string);
const setRecord = (s: AdvisoryState, r: unknown) => {
  s.recordText = `${JSON.stringify(r, null, 2)}\n`;
};
const regenerate = (s: AdvisoryState, claims: readonly Claim[] = CLAIMS) => {
  s.recordText = serializeHostAdvisoryRecord(deriveRecordWith(s, claims));
  return s;
};
const hostAudit = (s: AdvisoryState) =>
  (s.observation as NonNullable<AdvisoryState["observation"]>).lockfiles[0].audit as any;
const findingOf = (s: AdvisoryState, key: string) =>
  deriveHostAdvisoryRecord(s).findings.find((f) => f.key === key) as { reachability: string; bucket: string };

describe("SP1 host advisory record — the committed record and its two verdicts", function () {
  before(function () {
    REPO = advisoryStateFromRepo(".");
  });

  it("the committed record is ASSESSMENT_VALID, and the dependency status beside it is NOT_DEPENDENCY_SAFE", function () {
    const v = hostAdvisoryVerdict(fresh());
    expect(v.issues, JSON.stringify(v.issues, null, 2)).to.deep.equal([]);
    expect(v.assessment).to.equal("ASSESSMENT_VALID");
    expect(v.dependencyStatus).to.equal("NOT_DEPENDENCY_SAFE");
    expect(REPO.recordText).to.equal(serializeHostAdvisoryRecord(deriveHostAdvisoryRecord(fresh())));
  });

  it("records every current finding of zkvm/host/Cargo.lock: 12 vulnerabilities and 10 warnings, in the three buckets", function () {
    const r = deriveHostAdvisoryRecord(fresh());
    expect(r.assessment.counts.vulnerabilities).to.equal(12);
    expect(r.assessment.counts.warnings).to.equal(10);
    expect(r.assessment.counts.byKind).to.deep.equal({
      vulnerability: 12,
      unsound: 3,
      yanked: 1,
      unmaintained: 6,
      notice: 0,
    });
    expect(r.buckets.MUST_FIX_BEFORE_REAL_PROVING).to.deep.equal([]);
    expect(r.buckets.SHOULD_FIX_BEFORE_PRODUCTION).to.have.length(8);
    expect(r.buckets.NOT_REACHABLE_OR_UPSTREAM_ONLY).to.have.length(14);
    expect(r.findings.map((f) => f.bucket)).to.not.include("UNASSESSED");
    expect(r.findings.filter((f) => !f.compiled).map((f) => f.crate)).to.deep.equal(Array(5).fill("quinn-proto"));
  });

  it("binds the exact designated subject: d1, HEAD:zkvm/host, every host file, the lockfile", function () {
    const r = deriveHostAdvisoryRecord(fresh());
    const d1 = REPO.designations.find((d) => d.doc.id === OWNER_DECISION.designation);
    expect(r.subject.designation.id).to.equal("mldsa65-withdrawal-d1");
    expect(r.subject.designation.sha256).to.equal(d1?.sha256);
    expect(r.subject.zkvmHostTree).to.equal(d1?.doc.subject.zkvmHostTree);
    expect(r.subject.files.map((f) => f.path)).to.deep.equal([
      "zkvm/host/Cargo.lock",
      "zkvm/host/Cargo.toml",
      "zkvm/host/build.rs",
      "zkvm/host/src/main.rs",
    ]);
    expect(r.subject.lockfile.sha256).to.equal(sha256(REPO.locks.host as string));
    expect(r.ownerDecision.HOST_LOCKFILE_REMEDIATION).to.equal("DEFER_TO_NEXT_PROGRAM_REBUILD");
    expect(r.remediation.dependencyUpdatedByThisRecord).to.equal(false);
  });

  it("the companion lockfiles are vulnerability-free; guest and relation-tests carry three informational warnings each", function () {
    const r = deriveHostAdvisoryRecord(fresh());
    const by = Object.fromEntries(r.companionLockfiles.map((c) => [c.id, c]));
    expect(by.guest.vulnerabilities).to.equal(0);
    expect(by.guest.findings.map((f) => f.key)).to.deep.equal([
      "RUSTSEC-2026-0190 anyhow@1.0.102",
      "yanked der@0.8.0",
      "RUSTSEC-2025-0141 bincode@1.3.3",
    ]);
    expect(by["relation-tests"].findings.map((f) => f.key)).to.deep.equal(by.guest.findings.map((f) => f.key));
    expect(by["evidence-validator"].findings).to.deep.equal([]);
    expect(by["relation-tests"].findings.every((f) => f.bucket === "NOT_REACHABLE_OR_UPSTREAM_ONLY")).to.equal(true);
  });
});

describe("SP1 host advisory record — assessment validity is not dependency safety", function () {
  it("a record that claims DEPENDENCY_SAFE while vulnerabilities are locked is refused", function () {
    const s = fresh();
    const r = recordOf(s);
    r.assessment.dependencyStatus = "DEPENDENCY_SAFE";
    setRecord(s, r);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("RECORD_DEPENDENCY_STATUS_NOT_DERIVED");
    expect(v.assessment).to.equal("RECORD_INVALID");
    expect(v.dependencyStatus, "derived from the findings, never from the record").to.equal("NOT_DEPENDENCY_SAFE");
  });

  it("the dependency status is derived from the findings alone: only a vulnerability or unsoundness makes it unsafe", function () {
    expect(dependencyStatusOf(null)).to.equal("UNKNOWN");
    expect(dependencyStatusOf([])).to.equal("DEPENDENCY_SAFE");
    expect(dependencyStatusOf([{ kind: "unmaintained" }, { kind: "yanked" }])).to.equal("DEPENDENCY_SAFE");
    expect(dependencyStatusOf([{ kind: "unsound" }])).to.equal("NOT_DEPENDENCY_SAFE");
    expect(dependencyStatusOf([{ kind: "unmaintained" }, { kind: "vulnerability" }])).to.equal("NOT_DEPENDENCY_SAFE");
  });

  it("an unknown dependency status is reported when the lockfile is no longer the measured one", function () {
    const s = fresh();
    s.locks.host = `${s.locks.host}\n`;
    expect(hostAdvisoryVerdict(s).dependencyStatus).to.equal("UNKNOWN");
  });
});

describe("SP1 host advisory record — the designated subject moves", function () {
  it("a changed HEAD:zkvm/host tree with an unchanged record requires reassessment", function () {
    const s = fresh();
    s.headHostTree = "0".repeat(40);
    const v = hostAdvisoryVerdict(s);
    expect(v.assessment).to.equal("REASSESSMENT_REQUIRED");
    expect(codes(v)).to.include.members(["SUBJECT_TREE_CHANGED", "SUBJECT_FILE_CHANGED"]);
  });

  it("a changed zkvm/host/Cargo.lock requires re-measurement and reassessment", function () {
    const s = fresh();
    s.locks.host = (s.locks.host as string).replace(
      'name = "spin"\nversion = "0.9.8"',
      'name = "spin"\nversion = "0.9.9"',
    );
    expect(s.locks.host).to.not.equal(REPO.locks.host);
    const v = hostAdvisoryVerdict(s);
    expect(v.assessment).to.equal("REASSESSMENT_REQUIRED");
    expect(codes(v)).to.include("OBSERVATION_LOCKFILE_CHANGED");
  });

  it("a stale designation subject (the tripwire's errors) requires reassessment", function () {
    const s = fresh();
    s.designationFreshness = ["stale: the zkvm guest/host sources on disk are not d1's subject"];
    expect(codes(hostAdvisoryVerdict(s))).to.include("SUBJECT_STALE");
  });

  it("a successor designation supersedes the one the deferral was decided for", function () {
    const s = fresh();
    const d2 = structuredClone(s.designations[0]);
    d2.doc.id = "mldsa65-withdrawal-d2";
    d2.doc.sequence = 2;
    d2.path = "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json";
    s.designations.push(d2);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("SUBJECT_DESIGNATION_SUPERSEDED");
    expect(v.assessment).to.equal("REASSESSMENT_REQUIRED");
  });

  it("a record that restates d1 differently is refused (designations are immutable)", function () {
    const s = fresh();
    const r = recordOf(s);
    r.subject.designation.programVKey = `0x${"00".repeat(32)}`;
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_DESIGNATION_MISMATCH");
  });

  it("rewritten d1 bytes are refused against the record that bound them", function () {
    const s = fresh();
    s.designations[0].sha256 = "0".repeat(64);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_DESIGNATION_MISMATCH");
  });

  it("historical SP1 evidence the assessment read is never restamped: a changed digest requires reassessment", function () {
    const s = fresh();
    (s.td1Receipt as { sha256: string }).sha256 = "f".repeat(64);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("BOUND_EVIDENCE_CHANGED");
    expect(messages(v, "BOUND_EVIDENCE_CHANGED")).to.include("never restamped");
  });
});

describe("SP1 host advisory record — feature and runtime assumptions", function () {
  it("Cargo.toml enabling sp1-sdk's network feature breaks A_SP1_SDK_FEATURES and the claims resting on it", function () {
    const s = fresh();
    s.hostManifestText = (s.hostManifestText as string).replace(
      'features = ["blocking"]',
      'features = ["blocking", "network"]',
    );
    expect(s.hostManifestText).to.not.equal(REPO.hostManifestText);
    regenerate(s); // self-consistent: only the assumption layer can refuse
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include.members(["ASSUMPTION_FAILED", "CLAIM_UNSUPPORTED"]);
    expect(messages(v, "ASSUMPTION_FAILED")).to.include("A_SP1_SDK_FEATURES");
    expect(findingOf(s, H2).reachability).to.equal("UNSUPPORTED");
    expect(v.assessment).to.equal("REASSESSMENT_REQUIRED");
  });

  it("the network feature measured on in the feature tree breaks F_SP1_SDK_NO_NETWORK", function () {
    const s = fresh();
    const host = (s.observation as NonNullable<AdvisoryState["observation"]>).lockfiles[0];
    const sdk = host.features.find((f) => f.spec === "sp1-sdk@6.3.1") as { output: string };
    sdk.output = `${sdk.output}1sp1-sdk feature "network"\n`;
    regenerate(s);
    const v = hostAdvisoryVerdict(s);
    expect(messages(v, "EVIDENCE_FAILED")).to.include("F_SP1_SDK_NO_NETWORK");
    expect(findingOf(s, H2).reachability).to.equal("UNSUPPORTED");
    expect(findingOf(s, R0285).reachability).to.equal("UNSUPPORTED");
  });

  it("rustls's brotli feature measured on breaks RUSTSEC-2026-0348's claim", function () {
    const s = fresh();
    const host = (s.observation as NonNullable<AdvisoryState["observation"]>).lockfiles[0];
    const rustls = host.features.find((f) => f.spec === "rustls@0.23.40") as { output: string };
    rustls.output = `${rustls.output}1rustls feature "brotli"\n`;
    regenerate(s);
    const v = hostAdvisoryVerdict(s);
    expect(messages(v, "EVIDENCE_FAILED")).to.include("F_RUSTLS_NO_BROTLI");
    expect(findingOf(s, R0348).reachability).to.equal("UNSUPPORTED");
    expect(findingOf(s, R0348).bucket).to.equal("UNASSESSED");
  });

  it("a brotli crate in the lockfile, and a rustls dependency in the manifest, each break their assumption", function () {
    const s = fresh();
    const lock = parseCargoLock(s.locks.host as string);
    const input = (over: Partial<Parameters<(typeof ASSUMPTIONS)[number]["evaluate"]>[0]>) => ({
      hostManifestText: s.hostManifestText,
      hostMainText: s.hostMainText,
      hostLock: lock,
      provingAvailability: s.provingAvailability?.doc ?? null,
      archiveRecords: s.archiveRecords,
      ...over,
    });
    const evaluate = (id: string, over: Parameters<typeof input>[0]) =>
      (ASSUMPTIONS.find((a) => a.id === id) as (typeof ASSUMPTIONS)[number]).evaluate(input(over));
    expect(evaluate("A_LOCK_NO_BROTLI", {}).holds).to.equal(true);
    const withBrotli = [...lock, { name: "brotli", version: "8.0.0", source: null, checksum: null, dependencies: [] }];
    expect(evaluate("A_LOCK_NO_BROTLI", { hostLock: withBrotli }).holds).to.equal(false);
    const manifest = `${s.hostManifestText}rustls = { version = "0.23", features = ["brotli"] }\n`;
    expect(evaluate("A_HOST_MANIFEST", { hostManifestText: manifest }).holds).to.equal(false);
  });

  it("every assumption holds on the committed repository, and each fails on its own trigger", function () {
    const s = fresh();
    const lock = parseCargoLock(s.locks.host as string);
    const base = {
      hostManifestText: s.hostManifestText,
      hostMainText: s.hostMainText,
      hostLock: lock,
      provingAvailability: s.provingAvailability?.doc ?? null,
      archiveRecords: s.archiveRecords,
    };
    for (const a of ASSUMPTIONS) expect(a.evaluate(base).holds, a.id).to.equal(true);
    const add = (name: string) => [...lock, { name, version: "1.0.0", source: null, checksum: null, dependencies: [] }];
    const fails: Record<string, Partial<typeof base>> = {
      A_HOST_MANIFEST: { hostManifestText: `${s.hostManifestText}\n[features]\nnet = []\n` },
      A_SP1_SDK_FEATURES: {
        hostManifestText: (s.hostManifestText as string).replace(
          'version = "=6.3.1", features',
          'version = "=6.3.1", default-features = false, features',
        ),
      },
      A_LOCK_NO_NETWORK_CRATES: { hostLock: add("twirp") },
      A_LOCK_NO_CUDA: { hostLock: add("sp1-cuda") },
      A_LOCK_NO_AWS_LC: { hostLock: add("aws-lc-rs") },
      A_LOCK_NO_BROTLI: { hostLock: add("brotli-decompressor") },
      A_LOCK_BACKTRACE_WITHOUT_RUZSTD: {
        hostLock: lock.map((p) => (p.name === "backtrace" ? { ...p, dependencies: [...p.dependencies, "ruzstd"] } : p)),
      },
      A_HOST_SOURCE: { hostMainText: (s.hostMainText as string).replace(".groth16()", ".plonk()") },
      A_NO_PROVING_WITHOUT_ARCHIVE: { archiveRecords: ["evidence/zk/sp1-impl/proving-archives/v6.1.0.json"] },
    };
    expect(Object.keys(fails).sort()).to.deep.equal(ASSUMPTIONS.map((a) => a.id).sort());
    for (const a of ASSUMPTIONS) expect(a.evaluate({ ...base, ...fails[a.id] }).holds, a.id).to.equal(false);
  });

  it("A_HOST_SOURCE reads code, not comments: a comment naming the network prover is not a call", function () {
    const s = fresh();
    const lock = parseCargoLock(s.locks.host as string);
    const a = ASSUMPTIONS.find((x) => x.id === "A_HOST_SOURCE") as (typeof ASSUMPTIONS)[number];
    const input = (main: string) => ({
      hostManifestText: s.hostManifestText,
      hostMainText: main,
      hostLock: lock,
      provingAvailability: s.provingAvailability?.doc ?? null,
      archiveRecords: [],
    });
    expect(a.evaluate(input(`${s.hostMainText}\n// a network prover: .plonk()\n`)).holds).to.equal(true);
    expect(a.evaluate(input(`${s.hostMainText}\nfn n() { let _ = "x"; network(); }\n`)).holds).to.equal(false);
  });

  it("a WalletWall archive or a changed proving availability breaks the archive assumption behind rustls's condition", function () {
    const s = fresh();
    const pa = s.provingAvailability as { sha256: string; doc: any };
    pa.doc.status = "LOCAL_COPY_NOT_ARCHIVED";
    regenerate(s);
    const v = hostAdvisoryVerdict(s);
    expect(messages(v, "ASSUMPTION_FAILED")).to.include("A_NO_PROVING_WITHOUT_ARCHIVE");
    expect(findingOf(s, R0285).reachability).to.equal("UNSUPPORTED");
  });
});

describe("SP1 host advisory record — the record's findings", function () {
  it("an advisory deleted from the record is refused", function () {
    const s = fresh();
    const r = recordOf(s);
    r.findings = r.findings.filter((f: { key: string }) => f.key !== R0285);
    setRecord(s, r);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("RECORD_FINDING_OMITTED");
    expect(messages(v, "RECORD_FINDING_OMITTED")).to.include(R0285);
  });

  it("a changed advisory id in the record is an unknown finding and an omitted one", function () {
    const s = fresh();
    const r = recordOf(s);
    const f = r.findings.find((x: { key: string }) => x.key === R0285);
    f.id = "RUSTSEC-2026-9285";
    f.key = "RUSTSEC-2026-9285 rustls@0.23.40";
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include.members(["RECORD_FINDING_UNKNOWN", "RECORD_FINDING_OMITTED"]);
  });

  it("a crate version the lockfile does not pin is refused", function () {
    const s = fresh();
    const r = recordOf(s);
    const f = r.findings.find((x: { key: string }) => x.key === R0285);
    f.version = "0.23.46";
    f.key = "RUSTSEC-2026-0285 rustls@0.23.46";
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_FINDING_NOT_IN_LOCKFILE");
  });

  it("a duplicated finding is refused", function () {
    const s = fresh();
    const r = recordOf(s);
    r.findings.push(r.findings[0]);
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_FINDING_DUPLICATE");
  });

  it("a companion lockfile's finding deleted from the record, or invented in it, is refused by name", function () {
    const s = fresh();
    const r = recordOf(s);
    const guest = r.companionLockfiles.find((c: { id: string }) => c.id === "guest");
    const removed = guest.findings.shift();
    setRecord(s, r);
    expect(messages(hostAdvisoryVerdict(s), "RECORD_FINDING_OMITTED")).to.include(
      `zkvm/guest/Cargo.lock: ${removed.key}`,
    );
    guest.findings.unshift({ ...removed, key: "RUSTSEC-2099-0002 anyhow@1.0.102" });
    setRecord(s, r);
    expect(messages(hostAdvisoryVerdict(s), "RECORD_FINDING_UNKNOWN")).to.include(
      "zkvm/guest/Cargo.lock: RUSTSEC-2099-0002 anyhow@1.0.102",
    );
  });

  it("a package spec or version that is not exactly one cargo argument is refused before cargo runs", function () {
    expect(treeCommand("serde_json@1.0.151")).to.match(/ -i serde_json@1\.0\.151$/);
    expect(() => treeCommand("x@1.0.0 --manifest-path /etc/x")).to.throw("not a package spec");
    expect(() => treeCommand("--offline@1.0.0")).to.throw("not a package spec");
    expect(() => preciseProbeCommand("x@1.0.0", "1.0.1 --offline")).to.throw("not a package version");
  });

  it("a known finding reclassified as safe without evidence is refused at every field", function () {
    const s = fresh();
    const r = recordOf(s);
    const f = r.findings.find((x: { key: string }) => x.key === R0285);
    f.reachability = "NOT_COMPILED";
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_REACHABILITY_UNSUPPORTED");
    f.reachability = "CONDITIONAL";
    f.bucket = "NOT_REACHABLE_OR_UPSTREAM_ONLY";
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_BUCKET_NOT_DERIVED");
    f.bucket = "SHOULD_FIX_BEFORE_PRODUCTION";
    const g = r.findings.find((x: { key: string }) => x.key === R0346);
    g.evidence = [];
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_EVIDENCE_MISSING");
  });

  it("classification fields outside the vocabulary are refused", function () {
    const s = fresh();
    const r = recordOf(s);
    r.findings[0].reachability = "SAFE";
    r.findings[1].bucket = "LOW";
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include.members([
      "RECORD_REACHABILITY_UNSUPPORTED",
      "RECORD_BUCKET_NOT_DERIVED",
    ]);
  });

  it("fix facts and advisory fields are the measured ones", function () {
    const s = fresh();
    const r = recordOf(s);
    r.findings.find((x: { key: string }) => x.key === H2).fix.lockfileOnly = false;
    r.findings.find((x: { key: string }) => x.key === R0285).advisory.cvss = null;
    r.findings.find((x: { key: string }) => x.key === R0346).compiled = false;
    setRecord(s, r);
    expect(codes(hostAdvisoryVerdict(s))).to.include.members([
      "RECORD_FIX_NOT_DERIVED",
      "RECORD_ADVISORY_NOT_DERIVED",
      "RECORD_GRAPH_NOT_DERIVED",
    ]);
  });

  it("any other byte of the record that is not derived is drift", function () {
    const s = fresh();
    const r = recordOf(s);
    r.note = `${r.note} (edited)`;
    setRecord(s, r);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.deep.equal(["RECORD_DRIFT"]);
    expect(v.assessment).to.equal("RECORD_INVALID");
  });

  it("a missing or unparseable record, or a missing observation, is refused", function () {
    const s = fresh();
    s.recordText = null;
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_MISSING");
    s.recordText = "{ not json";
    expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_MALFORMED");
    const t = fresh();
    t.observation = null;
    const v = hostAdvisoryVerdict(t);
    expect(codes(v)).to.include("OBSERVATION_MISSING");
    expect(v.dependencyStatus).to.equal("UNKNOWN");
  });
});

describe("SP1 host advisory record — the deferral and the owner's premise", function () {
  for (const [what, edit] of [
    ["the owner's decision", (r: any) => (r.ownerDecision.HOST_LOCKFILE_REMEDIATION = "FIXED")],
    ["the remediation status", (r: any) => (r.remediation.status = "FIXED")],
    ["the dependency-update flag", (r: any) => (r.remediation.dependencyUpdatedByThisRecord = true)],
    ["a finding's disposition", (r: any) => (r.findings[0].disposition = "REMEDIATED")],
  ] as const) {
    it(`rewriting ${what} as fixed is refused`, function () {
      const s = fresh();
      const r = recordOf(s);
      edit(r);
      setRecord(s, r);
      expect(codes(hostAdvisoryVerdict(s))).to.include("RECORD_DEFERRAL_REWRITTEN");
    });
  }

  it("a MUST_FIX_BEFORE_REAL_PROVING finding fails the owner's premise, even in a self-consistent record", function () {
    const s = fresh();
    const claims = CLAIMS.map((c) =>
      c.id === "RUSTSEC-2026-0285"
        ? { ...c, reachability: "REACHABLE" as const, requires: [], condition: undefined }
        : c,
    );
    regenerate(s, claims);
    const v = evaluateHostAdvisories(s, claims);
    expect(codes(v)).to.include("PREMISE_FAILED");
    expect(deriveRecordWith(s, claims).buckets.MUST_FIX_BEFORE_REAL_PROVING).to.deep.equal([R0285]);
  });
});

describe("SP1 host advisory record — the claims catalog", function () {
  it("the reviewed catalog is consistent", function () {
    expect(catalogIssues()).to.deep.equal([]);
  });

  it("a judgment without measured evidence is refused, whatever assumptions it cites", function () {
    const claims = CLAIMS.map((c) => (c.id === "RUSTSEC-2026-0346" ? { ...c, requires: ["A_LOCK_NO_AWS_LC"] } : c));
    expect(catalogIssues(claims).map((i) => i.code)).to.include("CATALOG_UNSUPPORTED_JUDGMENT");
    const empty = CLAIMS.map((c) => (c.id === "RUSTSEC-2026-0346" ? { ...c, requires: [] } : c));
    expect(catalogIssues(empty).map((i) => i.code)).to.include("CATALOG_UNSUPPORTED_JUDGMENT");
  });

  it("a claim naming unknown evidence, a duplicate claim, or a misplaced condition is refused", function () {
    const unknown = CLAIMS.map((c) => (c.id === "RUSTSEC-2026-0346" ? { ...c, requires: ["SF_DOES_NOT_EXIST"] } : c));
    expect(catalogIssues(unknown).map((i) => i.code)).to.include("CATALOG_INVALID");
    expect(catalogIssues([...CLAIMS, CLAIMS[0]]).map((i) => i.code)).to.include("CATALOG_INVALID");
    const cond = CLAIMS.map((c) => (c.id === "RUSTSEC-2026-0346" ? { ...c, condition: "x" } : c));
    expect(catalogIssues(cond).map((i) => i.code)).to.include("CATALOG_INVALID");
  });

  it("a claim of NOT_COMPILED for a compiled crate is contradicted by the measured tree", function () {
    const s = fresh();
    const claims = CLAIMS.map((c) =>
      c.id === "RUSTSEC-2026-0285"
        ? { ...c, reachability: "NOT_COMPILED" as const, requires: [], condition: undefined }
        : c,
    );
    regenerate(s, claims);
    const v = evaluateHostAdvisories(s, claims);
    expect(codes(v)).to.include("CLAIM_UNSUPPORTED");
  });

  it("a measured advisory with no claim is UNASSESSED, never assessed by default", function () {
    const s = fresh();
    const audit = hostAudit(s);
    const twin = structuredClone(audit.vulnerabilities.list.find((x: any) => x.advisory.id === "RUSTSEC-2026-0258"));
    twin.advisory.id = "RUSTSEC-2099-0001";
    audit.vulnerabilities.list.push(twin);
    audit.vulnerabilities.count = audit.vulnerabilities.list.length;
    const before = hostAdvisoryVerdict(s);
    expect(codes(before)).to.include.members(["CLAIM_UNASSESSED", "RECORD_FINDING_OMITTED"]);
    regenerate(s);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("CLAIM_UNASSESSED");
    expect(v.assessment).to.equal("RECORD_INVALID");
  });

  it("a claim for a finding RustSec no longer reports must be removed, not kept as an allowance", function () {
    const s = fresh();
    const audit = hostAudit(s);
    audit.vulnerabilities.list = audit.vulnerabilities.list.filter((x: any) => x.advisory.id !== "RUSTSEC-2026-0285");
    audit.vulnerabilities.count = audit.vulnerabilities.list.length;
    regenerate(s);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("CLAIM_WITHOUT_FINDING");
    expect(messages(v, "CLAIM_WITHOUT_FINDING")).to.include("RUSTSEC-2026-0285");
  });

  it("evidence about callers must cover every locked dependent of the crate it is about", function () {
    const s = fresh();
    const lock = parseCargoLock(s.locks.host as string);
    expect(evidenceResults(s, lock).get("SF_NO_CUSTOM_SESSION_STORE")?.holds).to.equal(true);
    const sneaky = [
      ...lock,
      { name: "evil-tls", version: "1.0.0", source: null, checksum: null, dependencies: ["rustls"] },
    ];
    const r = evidenceResults(s, sneaky).get("SF_NO_CUSTOM_SESSION_STORE");
    expect(r?.holds).to.equal(false);
    expect(r?.observed).to.include("evil-tls");
  });
});

describe("SP1 host advisory record — the observation", function () {
  it("an observation made by another measurement script is stale", function () {
    const s = fresh();
    s.measureScriptSha256 = "0".repeat(64);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("OBSERVATION_SCRIPT_CHANGED");
    expect(v.assessment).to.equal("REASSESSMENT_REQUIRED");
  });

  it("a source fact measured with another pattern than the catalog's is stale", function () {
    const s = fresh();
    const obs = s.observation as NonNullable<AdvisoryState["observation"]>;
    obs.sourceFacts[0].pattern = `${obs.sourceFacts[0].pattern}|x`;
    expect(codes(hostAdvisoryVerdict(s))).to.include("OBSERVATION_CATALOG_CHANGED");
  });

  it("a source fact over zero files proves nothing", function () {
    const s = fresh();
    const obs = s.observation as NonNullable<AdvisoryState["observation"]>;
    const i = SOURCE_FACTS.findIndex((f) => f.id === "SF_PROVER_NO_ITER_MUT_OR_POP");
    obs.sourceFacts[i].crates[0].members = [];
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include.members(["OBSERVATION_MALFORMED"]);
  });

  it("a finding naming a version the lockfile does not pin is a malformed observation", function () {
    const s = fresh();
    hostAudit(s).vulnerabilities.list[0].package.version = "0.9.99";
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("OBSERVATION_MALFORMED");
    expect(messages(v, "OBSERVATION_MALFORMED")).to.include("does not pin");
  });

  it("a tree recorded under another command than the measured one is malformed", function () {
    const s = fresh();
    const obs = s.observation as NonNullable<AdvisoryState["observation"]>;
    obs.lockfiles[0].trees[0].command = "cargo tree";
    expect(codes(hostAdvisoryVerdict(s))).to.include("OBSERVATION_MALFORMED");
  });

  it("the observation was made with the pinned cargo-audit", function () {
    expect(REPO.observation?.tool.cargoAudit).to.match(new RegExp(` ${CARGO_AUDIT_VERSION.replace(/\./g, "\\.")}$`));
    const s = fresh();
    (s.observation as NonNullable<AdvisoryState["observation"]>).tool.cargoAudit = "cargo-audit-audit 0.21.0";
    expect(codes(hostAdvisoryVerdict(s))).to.include("OBSERVATION_MALFORMED");
  });
});

describe("SP1 host advisory record — companion lockfiles", function () {
  it("a clean companion lockfile that changes (e.g. a dependabot bump) does not fail the offline check", function () {
    const s = fresh();
    s.locks["evidence-validator"] = `${s.locks["evidence-validator"]}\n`;
    const v = hostAdvisoryVerdict(s);
    expect(v.issues, JSON.stringify(v.issues)).to.deep.equal([]);
    expect(v.assessment).to.equal("ASSESSMENT_VALID");
  });

  it("a companion lockfile that no longer pins a recorded finding's version is stale (the allowance would outlive the fix)", function () {
    const s = fresh();
    s.locks["relation-tests"] = (s.locks["relation-tests"] as string).replace(
      'name = "der"\nversion = "0.8.0"',
      'name = "der"\nversion = "0.8.2"',
    );
    expect(s.locks["relation-tests"]).to.not.equal(REPO.locks["relation-tests"]);
    const v = hostAdvisoryVerdict(s);
    expect(codes(v)).to.include("COMPANION_FINDING_NOT_IN_LOCKFILE");
    expect(messages(v, "COMPANION_FINDING_NOT_IN_LOCKFILE")).to.include("der@0.8.0");
  });

  it("the guest lockfile is designated: a change to it is a subject change", function () {
    const s = fresh();
    s.locks.guest = `${s.locks.guest}\n`;
    expect(codes(hostAdvisoryVerdict(s))).to.include("OBSERVATION_LOCKFILE_CHANGED");
  });
});

describe("SP1 host advisory record — the bucket rule", function () {
  const fix = (lockfileOnly: boolean): FixFacts => ({
    lockfileOnly,
    compatibleVersion: lockfileOnly ? "9.9.9" : null,
    alsoChanges: [],
    lowestPatched: null,
    upstreamBlocked: !lockfileOnly,
    blockedBy: null,
    noPatchedRelease: false,
  });
  const b = (
    kind: any,
    compiled: boolean,
    reachability: any,
    lockfileOnly: boolean,
    role: any = "DESIGNATED_SUBJECT",
  ) => bucketOf({ kind, compiled, reachability, fix: fix(lockfileOnly) }, role);

  it("derives each bucket from the facts", function () {
    expect(b("vulnerability", true, "REACHABLE", true)).to.equal("MUST_FIX_BEFORE_REAL_PROVING");
    expect(b("unsound", true, "REACHABLE", false)).to.equal("MUST_FIX_BEFORE_REAL_PROVING");
    expect(b("vulnerability", true, "CONDITIONAL", false)).to.equal("SHOULD_FIX_BEFORE_PRODUCTION");
    expect(b("vulnerability", true, "PRECONDITION_ABSENT", true)).to.equal("SHOULD_FIX_BEFORE_PRODUCTION");
    expect(b("yanked", true, "NO_KNOWN_DEFECT", true)).to.equal("SHOULD_FIX_BEFORE_PRODUCTION");
    expect(b("vulnerability", true, "PRECONDITION_ABSENT", false)).to.equal("NOT_REACHABLE_OR_UPSTREAM_ONLY");
    expect(b("vulnerability", false, "NOT_COMPILED", true)).to.equal("NOT_REACHABLE_OR_UPSTREAM_ONLY");
    expect(b("unmaintained", true, "NO_KNOWN_DEFECT", true)).to.equal("NOT_REACHABLE_OR_UPSTREAM_ONLY");
    expect(b("vulnerability", true, "UNSUPPORTED", true)).to.equal("UNASSESSED");
    expect(b("vulnerability", true, "UNASSESSED", true)).to.equal("UNASSESSED");
  });

  it("a lockfile that never ships is never in a before-production bucket", function () {
    expect(b("yanked", true, "NO_KNOWN_DEFECT", true, "CI_TEST_HARNESS")).to.equal("NOT_REACHABLE_OR_UPSTREAM_ONLY");
    expect(b("vulnerability", true, "REACHABLE", true, "OFFLINE_TOOLING")).to.equal("NOT_REACHABLE_OR_UPSTREAM_ONLY");
    expect(b("vulnerability", true, "UNSUPPORTED", true, "CI_TEST_HARNESS")).to.equal("UNASSESSED");
  });
});

describe("SP1 host advisory record — parsers and probes", function () {
  it("reads Cargo.lock packages and their dependency entries", function () {
    const lock = parseCargoLock(REPO.locks.host as string);
    expect(lock).to.have.length(537);
    expect(directDependents(lock, "rustls", "0.23.40")).to.deep.equal([
      "hyper-rustls@0.27.9",
      "quinn-proto@0.11.14",
      "quinn@0.11.9",
      "reqwest@0.12.28",
      "tokio-rustls@0.26.4",
    ]);
    const twice = parseCargoLock(
      '[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = [\n "b 1.0.0",\n]\n\n[[package]]\nname = "b"\nversion = "1.0.0"\n\n[[package]]\nname = "b"\nversion = "2.0.0"\n',
    );
    expect(directDependents(twice, "b", "1.0.0")).to.deep.equal(["a@1.0.0"]);
    expect(directDependents(twice, "b", "2.0.0")).to.deep.equal([]);
    expect(() => parseCargoLock("version = 4\n")).to.throw("no [[package]]");
  });

  it("reads the host manifest's TOML subset and refuses anything else", function () {
    const m = parseSimpleManifest(REPO.hostManifestText as string);
    expect(m.headers).to.deep.equal(["package", "[[bin]]", "dependencies", "build-dependencies"]);
    expect(m.entries.dependencies["sp1-sdk"]).to.deep.equal({ version: "=6.3.1", features: ["blocking"] });
    expect(parseSimpleManifest('[a]\nk = "v # not a comment" # a comment\n').entries.a.k).to.equal("v # not a comment");
    expect(() => parseSimpleManifest('[a]\nk = [\n "x",\n]\n')).to.throw("spanning lines");
    expect(() => parseSimpleManifest('[a]\nk = { x = "1",\n')).to.throw("spanning lines");
    expect(() => parseSimpleManifest("[a]\nk = 12\n")).to.throw("does not read");
    expect(() => parseSimpleManifest('[a]\nk = "1"\nk = "2"\n')).to.throw("set twice");
  });

  it("strips Rust comments but keeps strings, chars and raw strings", function () {
    expect(stripRustComments("a // x\nb /* c /* d */ e */ f")).to.equal("a \nb  f");
    expect(stripRustComments('let s = "// not a comment";')).to.equal('let s = "// not a comment";');
    expect(stripRustComments("let c = '\"'; // x")).to.equal("let c = '\"'; ");
    expect(stripRustComments('let r = r#"/* kept */"#;')).to.equal('let r = r#"/* kept */"#;');
    expect(stripRustComments("fn f<'a>(x: &'a str) {} // y")).to.equal("fn f<'a>(x: &'a str) {} ");
  });

  it("reads depth-prefixed cargo tree output", function () {
    expect(treeFactsOf("", "q", "1.0.0", "root")).to.deep.equal({
      compiled: false,
      role: "NOT_COMPILED",
      directDependents: [],
      pathToRoot: [],
    });
    const t = treeFactsOf(
      "0p v1.0.0 (proc-macro)\n1x v2.0.0\n2root v0.1.0 (zkvm/host)\n1y v3.0.0\n",
      "p",
      "1.0.0",
      "root",
    );
    expect(t).to.deep.equal({
      compiled: true,
      role: "PROC_MACRO",
      directDependents: ["x@2.0.0", "y@3.0.0"],
      pathToRoot: ["p@1.0.0", "x@2.0.0", "root@0.1.0"],
    });
    expect(treeFactsOf("0p v1.0.0\n1m v2.0.0 (proc-macro)\n2root v0.1.0\n", "p", "1.0.0", "root").role).to.equal(
      "PROC_MACRO_ONLY",
    );
    expect(
      treeFactsOf(
        "0p v1.0.0\n1m v2.0.0 (proc-macro)\n2root v0.1.0\n1n v2.0.0\n2root v0.1.0 (*)\n",
        "p",
        "1.0.0",
        "root",
      ).role,
    ).to.equal("LINKED");
    expect(() => treeFactsOf("0p v1.0.0\n1x v2.0.0\n", "p", "1.0.0", "root")).to.throw("does not reach");
    expect(() => treeFactsOf("0q v1.0.0\n", "p", "1.0.0", "root")).to.throw("not the inverted tree");
    expect(() => treeFactsOf("├── p v1.0.0\n", "p", "1.0.0", "root")).to.throw("not a depth-prefixed");
  });

  it("reads a crate's own features, never a similarly named crate's", function () {
    const out =
      '0rustls v0.23.40\n1rustls feature "ring"\n2hyper-rustls feature "http2"\n1hyper-rustls feature "brotli"\n';
    expect(featuresOf(out, "rustls", "0.23.40")).to.deep.equal(["ring"]);
    expect(() => featuresOf(out, "rustls", "0.23.41")).to.throw("not the inverted feature tree");
  });

  it("reads dry-run update and precise probes", function () {
    const up =
      "    Updating crates.io index\n     Locking 2 packages to latest compatible versions\n    Updating rustls v0.23.40 -> v0.23.46\n    Updating rustls-webpki v0.103.13 -> v0.103.15\nwarning: not updating lockfile due to dry run\n";
    expect(updateProbeOf(up, "rustls", "0.23.40")).to.deep.equal({ to: "0.23.46" });
    expect(updateChangesOf(up, "rustls", "0.23.40")).to.deep.equal(["Updating rustls-webpki v0.103.13 -> v0.103.15"]);
    expect(
      updateProbeOf("     Locking 0 packages\nwarning: not updating lockfile due to dry run\n", "lru", "0.12.5"),
    ).to.deep.equal({ to: null });
    expect(() => updateProbeOf("error: no such package\n", "lru", "0.12.5")).to.throw("failed");
    expect(() => updateProbeOf("Updating lru v0.12.5 -> v0.12.6\n", "lru", "0.12.5")).to.throw("not a dry-run");
    const blocked =
      'error: failed to select a version for the requirement `lru = "^0.12.4"`\ncandidate versions found which didn\'t match: 0.16.3\nrequired by package `sp1-prover v6.3.1`\n';
    expect(preciseProbeOf(blocked, "lru", "0.12.5")).to.deep.equal({
      blocked: true,
      requirement: 'lru = "^0.12.4"',
      requiredBy: "sp1-prover v6.3.1",
    });
    expect(preciseProbeOf("    Updating lru v0.12.5 -> v0.16.3\n", "lru", "0.12.5")).to.deep.equal({
      blocked: false,
      to: "0.16.3",
    });
    expect(() => preciseProbeOf("something else\n", "lru", "0.12.5")).to.throw("neither updated nor named");
  });

  it("compares versions and reads RustSec requirements the way Cargo does", function () {
    expect(satisfies("0.4.20", ">=0.4.16")).to.equal(true);
    expect(satisfies("0.4.15", ">=0.4.16")).to.equal(false);
    expect(satisfies("0.9.5", "^0.9.1")).to.equal(true);
    expect(satisfies("0.10.0", "^0.9.1")).to.equal(false);
    expect(satisfies("1.9.0", "^1.2")).to.equal(true);
    expect(satisfies("2.0.0", "^1.2")).to.equal(false);
    expect(satisfies("0.0.3", "^0.0.3")).to.equal(true);
    expect(satisfies("0.0.4", "^0.0.3")).to.equal(false);
    expect(satisfies("1.2.9", "~1.2.3")).to.equal(true);
    expect(satisfies("1.3.0", "~1.2.3")).to.equal(false);
    expect(satisfies("1.3.0", ">= 1.2, < 1.5")).to.equal(true);
    expect(satisfies("1.5.0", ">= 1.2, < 1.5")).to.equal(false);
    expect(satisfies("1.0.0", "=1.0.0")).to.equal(true);
    expect(satisfies("1.0.1", "> 1.0.0")).to.equal(true);
    expect(satisfies("1.0.0", "<= 1.0.0")).to.equal(true);
    expect(satisfies("0.9.0", "0.9")).to.equal(true);
    expect(compareVersions("1.0.0-rc.1", "1.0.0")).to.equal(-1);
    expect(compareVersions("1.0.0-rc.2", "1.0.0-rc.10")).to.equal(-1);
    expect(compareVersions("1.0.0-alpha", "1.0.0-1")).to.equal(1);
    expect(compareVersions("1.0.0-rc.1", "1.0.0-rc.1.1")).to.equal(-1);
    expect(compareVersions("1.0.0", "1.0.0")).to.equal(0);
    expect(minimalPatchedVersion([">=0.18.2", ">=0.16.3, <0.17.0"])).to.equal("0.16.3");
    expect(() => minimalPatchedVersion(["<0.9.0"])).to.throw("no lower bound");
    expect(() => satisfies("1.0.0", "1.0 || 2.0")).to.throw("does not read");
    expect(() => compareVersions("x", "1.0.0")).to.throw("not a version");
  });

  it("derives fix facts: compatible, upstream-blocked, no patched release, yanked", function () {
    const f = (kind: any, patched: string[]): MeasuredFinding => ({
      lockfile: "host",
      kind,
      id: kind === "yanked" ? null : "RUSTSEC-2026-0001",
      crate: "c",
      version: "1.0.0",
      advisory:
        kind === "yanked"
          ? null
          : {
              title: "t",
              date: "2026-01-01",
              categories: [],
              cvss: null,
              informational: null,
              withdrawn: null,
              patched,
              unaffected: [],
              functions: null,
              url: null,
            },
    });
    const dry = (line: string) => `${line}\nwarning: not updating lockfile due to dry run\n`;
    const never = () => {
      throw new Error("no precise probe expected");
    };
    expect(fixFactsOf(f("vulnerability", [">=1.0.5"]), dry("    Updating c v1.0.0 -> v1.0.7"), never)).to.include({
      lockfileOnly: true,
      compatibleVersion: "1.0.7",
      lowestPatched: "1.0.5",
    });
    const blocked = fixFactsOf(
      f("unsound", [">=2.0.0"]),
      dry("     Locking 0 packages"),
      () => 'failed to select a version for the requirement `c = "^1.0"`\nrequired by package `p v1.0.0`\n',
    );
    expect(blocked).to.include({
      lockfileOnly: false,
      upstreamBlocked: true,
      blockedBy: 'p v1.0.0 requires c = "^1.0"',
    });
    expect(fixFactsOf(f("unmaintained", []), dry(""), never)).to.include({
      noPatchedRelease: true,
      lockfileOnly: false,
    });
    expect(fixFactsOf(f("yanked", []), dry("    Updating c v1.0.0 -> v1.0.1"), never)).to.include({
      lockfileOnly: true,
      compatibleVersion: "1.0.1",
    });
    expect(fixFactsOf(f("yanked", []), dry(""), never)).to.include({ lockfileOnly: false, upstreamBlocked: true });
  });

  it("reads the crates.io sparse index: paths, entries, yanked releases; an unlisted or re-checksummed package fails", function () {
    expect(sparseIndexPath("a")).to.equal("1/a");
    expect(sparseIndexPath("ab")).to.equal("2/ab");
    expect(sparseIndexPath("abc")).to.equal("3/a/abc");
    expect(sparseIndexPath("Serde_JSON")).to.equal("se/rd/serde_json");
    expect(() => sparseIndexPath("../x")).to.throw("not a crate name");
    const ck = "a".repeat(64);
    const text = `{"name":"spin","vers":"0.9.8","cksum":"${ck}","yanked":true}\n{"name":"spin","vers":"0.9.9","cksum":"${"b".repeat(64)}","yanked":false}\n`;
    const entries = indexEntriesOf(text, "spin");
    expect(entries.get("0.9.8")).to.deep.equal({ cksum: ck, yanked: true });
    expect(() => indexEntriesOf(`{"name":"other","vers":"1.0.0","cksum":"${ck}","yanked":false}`, "spin")).to.throw(
      "has an entry for",
    );
    expect(() => indexEntriesOf(`{"name":"spin","vers":"1.0.0","yanked":false}`, "spin")).to.throw("no checksum");
    const pkg = {
      name: "spin",
      version: "0.9.8",
      source: "registry+https://github.com/rust-lang/crates.io-index",
      checksum: ck,
      dependencies: [],
    };
    const index = new Map([["spin", entries]]);
    expect(yankedPackages([pkg], index)).to.deep.equal([{ crate: "spin", version: "0.9.8" }]);
    expect(() => yankedPackages([{ ...pkg, version: "0.9.7" }], index)).to.throw("yanked status unmeasured");
    expect(() => yankedPackages([{ ...pkg, checksum: "c".repeat(64) }], index)).to.throw("another checksum");
    expect(yankedPackages([{ ...pkg, source: null }], index), "a path dependency is not the index's").to.deep.equal([]);
  });

  it("normalizes temporary paths in cargo output and refuses one it could not", function () {
    expect(normalizeCargoOutput("0x v1.0.0\n1root v0.1.0 (C:\\T\\wv-1\\zkvm\\host)\r\n", "C:\\T\\wv-1")).to.equal(
      "0x v1.0.0\n1root v0.1.0 (zkvm/host)\n",
    );
    expect(normalizeCargoOutput("1root v0.1.0 (/tmp/wv-1/zkvm/relation-tests/shim)\n", "/tmp/wv-1")).to.equal(
      "1root v0.1.0 (zkvm/relation-tests/shim)\n",
    );
    expect(() => normalizeCargoOutput("1root v0.1.0 (D:\\elsewhere\\zkvm\\host)\n", "C:\\T\\wv-1")).to.throw(
      "absolute path",
    );
  });

  it("refuses a cargo-audit report that is not a --no-yanked one, or not the lockfile's", function () {
    const lock = parseCargoLock(REPO.locks.host as string);
    const report = structuredClone(hostAudit(REPO));
    expect(auditFindingsOf(report, "host", lock)).to.have.length(21);
    const yanked = structuredClone(report);
    yanked.warnings.yanked = [];
    expect(() => auditFindingsOf(yanked, "host", lock)).to.throw("--no-yanked");
    const counted = structuredClone(report);
    counted.lockfile["dependency-count"] = 536;
    expect(() => auditFindingsOf(counted, "host", lock)).to.throw("counts 536");
    const mislabeled = structuredClone(report);
    mislabeled.warnings.unsound[0].advisory.informational = null;
    expect(() => auditFindingsOf(mislabeled, "host", lock)).to.throw("RustSec marks it");
    const withdrawn = structuredClone(report);
    withdrawn.vulnerabilities.list[0].advisory.withdrawn = "2026-10-01";
    expect(() => auditFindingsOf(withdrawn, "host", lock)).to.throw("withdrawn");
    const empty = structuredClone(report);
    empty.database["advisory-count"] = 0;
    expect(() => auditFindingsOf(empty, "host", lock)).to.throw("empty advisory database");
    const inconsistent = structuredClone(report);
    inconsistent.vulnerabilities.count = 3;
    expect(() => auditFindingsOf(inconsistent, "host", lock)).to.throw("inconsistent");
  });

  it("counts source-fact matches over exactly the selected members", function () {
    const fact = SOURCE_FACTS.find(
      (f) => f.id === "SF_SDK_GRPC_ONLY_IN_NETWORK_MODULE",
    ) as (typeof SOURCE_FACTS)[number];
    expect(memberSelected(fact.select, "src/lib.rs")).to.equal(true);
    expect(memberSelected(fact.select, "src/network/client.rs")).to.equal(false);
    expect(memberSelected(fact.select, "build.rs")).to.equal(false);
    expect(countMatches(fact, "use tonic::Status; tonic::x")).to.equal(2);
    const only = SOURCE_FACTS.find(
      (f) => f.id === "SF_PROVER_HTTP_CLIENT_ONLY_IN_BUILD_RS",
    ) as (typeof SOURCE_FACTS)[number];
    const obs = (members: { path: string; matches: number }[]) => ({
      id: only.id,
      pattern: only.pattern,
      flags: only.flags,
      crates: [
        {
          crate: "sp1-prover",
          version: "6.3.1",
          checksum: "x",
          members: members.map((m) => ({ ...m, sha256: "0".repeat(64) })),
        },
      ],
    });
    expect(
      sourceFactResult(
        only,
        obs([
          { path: "src/build.rs", matches: 1 },
          { path: "src/a.rs", matches: 0 },
        ]),
      ).holds,
    ).to.equal(true);
    expect(sourceFactResult(only, obs([{ path: "src/a.rs", matches: 1 }])).holds).to.equal(false);
    expect(sourceFactResult(only, obs([{ path: "src/build.rs", matches: 0 }])).holds, "onlyIn needs a match").to.equal(
      false,
    );
    expect(sourceFactResult(only, obs([])).holds, "no file read proves nothing").to.equal(false);
  });

  it("the record lists the lockfiles host first and names the committed path", function () {
    expect(LOCKFILES.map((l) => l.id)).to.deep.equal(["host", "guest", "relation-tests", "evidence-validator"]);
    expect(HOST_ADVISORIES_REL).to.equal("evidence/zk/sp1-impl/host-lockfile-advisories.json");
  });
});

describe("SP1 host advisory record — the owner-facing doc", function () {
  const doc = readFileSync(ADVISORIES_DOC_REL, "utf8");

  it("the doc's findings table is the record's, row for row", function () {
    const rows = [...doc.matchAll(/^\| `([^`]+)` \| (\w+) \| (yes|\*\*no\*\*) \| (\w+) \| (\w+) \| [^|]+ \|$/gm)].map(
      (m) => ({
        key: m[1],
        kind: m[2],
        compiled: m[3] === "yes",
        reachability: m[4],
        bucket: m[5],
      }),
    );
    const r = deriveHostAdvisoryRecord(fresh());
    expect(rows).to.deep.equal(
      r.findings.map((f) => ({
        key: f.key,
        kind: f.kind,
        compiled: f.compiled,
        reachability: f.reachability,
        bucket: f.bucket,
      })),
    );
  });

  it("states the bucket counts, the owner's decision and that the record is not a waiver", function () {
    const r = deriveHostAdvisoryRecord(fresh());
    for (const [b, keys] of Object.entries(r.buckets)) expect(doc).to.include(`| \`${b}\` | ${keys.length} |`);
    expect(doc).to.include("`HOST_LOCKFILE_REMEDIATION = DEFER_TO_NEXT_PROGRAM_REBUILD`");
    expect(doc).to.include("It does not make a vulnerable dependency non-vulnerable.");
    expect(doc).to.include("This is not a security waiver");
  });
});
