/**
 * RustSec drift (scripts/lib/sp1-host-advisories.ts rustsecDrift; scripts/check-rustsec-drift.ts): what the networked,
 * reporting-only workflow concludes from a fresh measurement of the four lockfiles against the committed record.
 *
 * Identities are exact (lockfile, kind, advisory id, crate, version): a new advisory turns red even for a crate the
 * record already covers, a justification never moves to another version or lockfile, a disappeared finding asks for
 * cleanup, and a live measurement that is missing or malformed is AUDIT_UNAVAILABLE, never a clean MATCH. Each live
 * observation below is the committed one with exactly one change.
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DRIFT_EXIT,
  advisoryStateFromRepo,
  fixStateOf,
  rustsecDrift,
  type AdvisoryObservation,
  type DriftReport,
  type HostAdvisoryRecord,
  type LockfileId,
} from "../scripts/lib/sp1-host-advisories";

let RECORD: HostAdvisoryRecord;
let OBS: AdvisoryObservation;
let LOCKS: Record<LockfileId, string | null>;
const live = (): AdvisoryObservation => structuredClone(OBS);
const types = (r: DriftReport) => [...new Set(r.items.map((i) => i.type))].sort();
const keys = (r: DriftReport, type: string) =>
  r.items.filter((i) => i.type === type).map((i) => `${i.lockfile} ${i.key}`);
const audit = (o: AdvisoryObservation, i = 0) => o.lockfiles[i].audit as any;
const vuln = (o: AdvisoryObservation, id: string) =>
  structuredClone(audit(o).vulnerabilities.list.find((x: any) => x.advisory.id === id));
const push = (o: AdvisoryObservation, item: unknown, i = 0) => {
  const v = audit(o, i).vulnerabilities;
  v.list.push(item);
  v.count = v.list.length;
  v.found = true;
};

describe("RustSec drift — reconciling a fresh measurement with the committed record", function () {
  before(function () {
    const s = advisoryStateFromRepo(".");
    RECORD = JSON.parse(s.recordText as string) as HostAdvisoryRecord;
    OBS = s.observation as AdvisoryObservation;
    LOCKS = s.locks;
  });

  it("the committed observation, measured again unchanged, is a MATCH of all 30 recorded findings", function () {
    const r = rustsecDrift(RECORD, live(), LOCKS);
    expect(r.items).to.deep.equal([]);
    expect(r.verdict).to.equal("MATCH");
    expect(r.known).to.equal(30);
    expect(DRIFT_EXIT[r.verdict]).to.equal(0);
  });

  it("a new advisory against a compiled crate is SECURITY_DRIFT", function () {
    const o = live();
    const twin = vuln(o, "RUSTSEC-2026-0258");
    twin.advisory.id = "RUSTSEC-2099-0001";
    push(o, twin);
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(r.verdict).to.equal("SECURITY_DRIFT");
    expect(keys(r, "NEW_FINDING")).to.deep.equal(["host RUSTSEC-2099-0001 h2@0.4.14"]);
    expect(DRIFT_EXIT[r.verdict]).to.equal(1);
  });

  it("an existing justification cannot cover a different advisory against the same crate and version", function () {
    const o = live();
    const twin = vuln(o, "RUSTSEC-2026-0285");
    twin.advisory.id = "RUSTSEC-2099-0285";
    push(o, twin);
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(keys(r, "NEW_FINDING")).to.deep.equal(["host RUSTSEC-2099-0285 rustls@0.23.40"]);
    expect(r.verdict).to.equal("SECURITY_DRIFT");
  });

  it("a finding RustSec no longer reports asks for the record to be cleaned up (and is not a match)", function () {
    const o = live();
    const v = audit(o).vulnerabilities;
    v.list = v.list.filter((x: any) => x.advisory.id !== "RUSTSEC-2026-0285");
    v.count = v.list.length;
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(types(r)).to.deep.equal(["DISAPPEARED"]);
    expect(r.verdict).to.equal("RECORD_CLEANUP_REQUIRED");
    expect(DRIFT_EXIT[r.verdict]).to.equal(2);
  });

  it("a warning that becomes a vulnerability is a changed kind, not a new finding", function () {
    const o = live();
    const w = audit(o).warnings;
    const moved = w.unsound.find((x: any) => x.advisory.id === "RUSTSEC-2026-0002");
    w.unsound = w.unsound.filter((x: any) => x !== moved);
    delete moved.kind;
    moved.advisory.informational = null;
    push(o, moved);
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(keys(r, "KIND_CHANGED")).to.deep.equal(["host RUSTSEC-2026-0002 lru@0.12.5"]);
    expect(keys(r, "NEW_FINDING")).to.deep.equal([]);
    expect(r.verdict).to.equal("SECURITY_DRIFT");
  });

  for (const [field, edit] of [
    ["severity (cvss)", (a: any) => (a.advisory.cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")],
    ["category", (a: any) => (a.advisory.categories = ["code-execution"])],
    ["patched range", (a: any) => (a.versions.patched = [">=0.23.46"])],
    ["title", (a: any) => (a.advisory.title = "A different flaw")],
  ] as const) {
    it(`a changed ${field} of a recorded advisory is SECURITY_DRIFT`, function () {
      const o = live();
      const entry = audit(o).vulnerabilities.list.find((x: any) => x.advisory.id === "RUSTSEC-2026-0285");
      const before = JSON.stringify(entry);
      edit(entry);
      expect(JSON.stringify(entry), "the edit must change the advisory").to.not.equal(before);
      const r = rustsecDrift(RECORD, o, LOCKS);
      expect(keys(r, "ADVISORY_CHANGED")).to.deep.equal(["host RUSTSEC-2026-0285 rustls@0.23.40"]);
      expect(r.verdict).to.equal("SECURITY_DRIFT");
    });
  }

  it("a reworded description alone is not drift", function () {
    const o = live();
    audit(o).vulnerabilities.list[0].advisory.description = "reworded";
    expect(rustsecDrift(RECORD, o, LOCKS).verdict).to.equal("MATCH");
  });

  it("the same advisory against another crate version, in a changed lockfile, is version and lockfile drift", function () {
    const o = live();
    const host = o.lockfiles[0];
    host.sha256 = "0".repeat(64);
    const m = audit(o).warnings.unsound.find((x: any) => x.advisory.id === "RUSTSEC-2026-0186");
    m.package.version = "0.9.9";
    const retarget = (e: { spec: string; command: string; output: string }) => {
      e.spec = "memmap2@0.9.9";
      e.command = e.command.replace("memmap2@0.9.10", "memmap2@0.9.9");
      e.output = e.output.split("memmap2 v0.9.10").join("memmap2 v0.9.9");
    };
    retarget(host.trees.find((t) => t.spec === "memmap2@0.9.10") as never);
    retarget(host.updates.find((t) => t.spec === "memmap2@0.9.10") as never);
    const r = rustsecDrift(RECORD, o, {});
    expect(keys(r, "VERSION_DRIFT")).to.deep.equal(["host RUSTSEC-2026-0186 memmap2@0.9.10"]);
    expect(types(r)).to.include("LOCKFILE_DRIFT");
    expect(r.verdict).to.equal("SECURITY_DRIFT");
  });

  it("a crate that becomes compiled is graph drift", function () {
    const o = live();
    const t = o.lockfiles[0].trees.find((x) => x.spec === "quinn-proto@0.11.14") as { output: string };
    t.output =
      "0quinn-proto v0.11.14\n1quinn v0.11.9\n2reqwest v0.12.28\n3sp1-prover v6.3.1\n4sp1-sdk v6.3.1\n5mldsa65-host v0.1.0 (zkvm/host)\n";
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(keys(r, "GRAPH_DRIFT")).to.have.length(5);
    expect(r.verdict).to.equal("SECURITY_DRIFT");
  });

  it("a fix that becomes available (or stops being) is fix drift", function () {
    const o = live();
    const u = o.lockfiles[0].updates.find((x) => x.spec === "lru@0.12.5") as { output: string };
    u.output = "    Updating lru v0.12.5 -> v0.18.2\nwarning: not updating lockfile due to dry run\n";
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(keys(r, "FIX_DRIFT")).to.deep.equal([
      "host RUSTSEC-2026-0002 lru@0.12.5",
      "host RUSTSEC-2026-0253 lru@0.12.5",
    ]);
  });

  it("a re-measured source or feature fact that no longer holds is evidence drift", function () {
    const o = live();
    const sf = o.sourceFacts.find(
      (f) => f.id === "SF_PROVER_NO_ITER_MUT_OR_POP",
    ) as AdvisoryObservation["sourceFacts"][number];
    sf.crates[0].members[0].matches = 1;
    const rustls = o.lockfiles[0].features.find((f) => f.spec === "rustls@0.23.40") as { output: string };
    rustls.output = `${rustls.output}1rustls feature "brotli"\n`;
    const r = rustsecDrift(RECORD, o, LOCKS);
    expect(keys(r, "EVIDENCE_DRIFT")).to.deep.equal(["host F_RUSTLS_NO_BROTLI", "host SF_PROVER_NO_ITER_MUT_OR_POP"]);
    expect(r.verdict).to.equal("SECURITY_DRIFT");
  });

  it("a host advisory appearing in a clean lockfile is new there: justifications never cross lockfiles", function () {
    const o = live();
    const ev = o.lockfiles[3];
    const host = o.lockfiles[0];
    push(o, vuln(o, "RUSTSEC-2026-0285"), 3);
    ev.trees.push(structuredClone(host.trees.find((t) => t.spec === "rustls@0.23.40") as never));
    ev.updates.push(structuredClone(host.updates.find((t) => t.spec === "rustls@0.23.40") as never));
    (ev.trees.at(-1) as { output: string }).output =
      "0rustls v0.23.40\n1evidence-validator v0.1.0 (zkvm/evidence-validator)\n";
    const r = rustsecDrift(RECORD, o, {});
    expect(keys(r, "NEW_FINDING")).to.deep.equal(["evidence-validator RUSTSEC-2026-0285 rustls@0.23.40"]);
  });

  it("the clean lockfile stays clean, and its recorded state is empty", function () {
    expect(RECORD.companionLockfiles.find((c) => c.id === "evidence-validator")?.findings).to.deep.equal([]);
    const r = rustsecDrift(RECORD, live(), LOCKS);
    expect(r.items.filter((i) => i.lockfile === "evidence-validator")).to.deep.equal([]);
  });

  const unusable: [string, (o: AdvisoryObservation) => unknown][] = [
    ["no observation at all", () => null],
    ["an empty object", () => ({})],
    ["another schema", (o) => ({ ...o, schema: "other" })],
    ["three lockfiles", (o) => ({ ...o, lockfiles: o.lockfiles.slice(0, 3) })],
    ["no advisory database", (o) => ({ ...o, database: { ...o.database, lastCommit: null } })],
    [
      "an inconsistent cargo-audit report",
      (o) => {
        audit(o).vulnerabilities.count = 99;
        return o;
      },
    ],
    [
      "a missing tree for a finding",
      (o) => {
        o.lockfiles[0].trees = o.lockfiles[0].trees.slice(1);
        return o;
      },
    ],
  ];
  for (const [what, make] of unusable) {
    it(`a live measurement with ${what} is AUDIT_UNAVAILABLE, never a match`, function () {
      const r = rustsecDrift(RECORD, make(live()), LOCKS);
      expect(r.verdict).to.equal("AUDIT_UNAVAILABLE");
      expect(types(r)).to.deep.equal(["UNAVAILABLE"]);
      expect(DRIFT_EXIT[r.verdict]).to.equal(3);
    });
  }

  it("a live measurement of other lockfiles than the checkout's is AUDIT_UNAVAILABLE", function () {
    const r = rustsecDrift(RECORD, live(), { ...LOCKS, host: `${LOCKS.host}\n` });
    expect(r.verdict).to.equal("AUDIT_UNAVAILABLE");
  });

  it("the four outcomes have four distinct exit codes", function () {
    expect(new Set(Object.values(DRIFT_EXIT)).size).to.equal(4);
    expect(DRIFT_EXIT).to.deep.equal({ MATCH: 0, SECURITY_DRIFT: 1, RECORD_CLEANUP_REQUIRED: 2, AUDIT_UNAVAILABLE: 3 });
  });

  it("a live measurement whose lockfiles are not the four named ones is AUDIT_UNAVAILABLE", function () {
    const o = live();
    (o.lockfiles[3] as { id: string }).id = "other";
    expect(rustsecDrift(RECORD, o, LOCKS).verdict).to.equal("AUDIT_UNAVAILABLE");
  });

  it("graph drift is reported for a changed role alone and for changed dependents alone", function () {
    const role = live();
    const t = role.lockfiles[0].trees.find((x) => x.spec === "memmap2@0.9.10") as { output: string };
    t.output = t.output
      .split("\n")
      .map((l) => l.replace(/^(1\S+ v\S+)/, "$1 (proc-macro)"))
      .join("\n");
    const byRole = rustsecDrift(RECORD, role, LOCKS);
    expect(keys(byRole, "GRAPH_DRIFT")).to.deep.equal(["host RUSTSEC-2026-0186 memmap2@0.9.10"]);
    expect(byRole.items.find((i) => i.type === "GRAPH_DRIFT")?.detail).to.include("role PROC_MACRO_ONLY");
    const deps = live();
    const u = deps.lockfiles[0].trees.find((x) => x.spec === "memmap2@0.9.10") as { output: string };
    u.output = `${u.output}1newcomer v1.0.0\n2mldsa65-host v0.1.0 (zkvm/host) (*)\n`;
    const byDeps = rustsecDrift(RECORD, deps, LOCKS);
    expect(keys(byDeps, "GRAPH_DRIFT")).to.deep.equal(["host RUSTSEC-2026-0186 memmap2@0.9.10"]);
    expect(byDeps.items.find((i) => i.type === "GRAPH_DRIFT")?.detail).to.include("newcomer@1.0.0");
  });

  it("fix drift is reported between every two fix states", function () {
    const blockedToNone = live();
    for (const w of audit(blockedToNone).warnings.unsound.filter((x: any) => x.package.name === "lru")) {
      w.versions.patched = [];
    }
    const a = rustsecDrift(RECORD, blockedToNone, LOCKS);
    expect(keys(a, "FIX_DRIFT")).to.deep.equal([
      "host RUSTSEC-2026-0002 lru@0.12.5",
      "host RUSTSEC-2026-0253 lru@0.12.5",
    ]);
    expect(a.items.find((i) => i.type === "FIX_DRIFT")?.detail).to.equal(
      "fix availability changed from UPSTREAM_BLOCKED to NO_PATCHED_RELEASE",
    );
    const fixToNone = live();
    audit(fixToNone).vulnerabilities.list.find((x: any) => x.advisory.id === "RUSTSEC-2026-0346").versions.patched = [];
    expect(keys(rustsecDrift(RECORD, fixToNone, LOCKS), "FIX_DRIFT")).to.deep.equal([
      "host RUSTSEC-2026-0346 rustls@0.23.40",
    ]);
  });

  it("a fix state is exactly one of three, and a fix in none or two of them is refused", function () {
    const base = { compatibleVersion: null, alsoChanges: [], lowestPatched: null, blockedBy: null };
    expect(fixStateOf({ ...base, lockfileOnly: true, upstreamBlocked: false, noPatchedRelease: false })).to.equal(
      "LOCKFILE_ONLY",
    );
    expect(fixStateOf({ ...base, lockfileOnly: false, upstreamBlocked: true, noPatchedRelease: false })).to.equal(
      "UPSTREAM_BLOCKED",
    );
    expect(fixStateOf({ ...base, lockfileOnly: false, upstreamBlocked: false, noPatchedRelease: true })).to.equal(
      "NO_PATCHED_RELEASE",
    );
    expect(() =>
      fixStateOf({ ...base, lockfileOnly: false, upstreamBlocked: false, noPatchedRelease: false }),
    ).to.throw("0 states");
    expect(() => fixStateOf({ ...base, lockfileOnly: true, upstreamBlocked: true, noPatchedRelease: false })).to.throw(
      "2 states",
    );
  });
});

describe("RustSec drift — the check-rustsec-drift CLI", function () {
  this.timeout(120_000);
  let dir: string;
  before(function () {
    dir = mkdtempSync(join(tmpdir(), "wv-drift-"));
  });
  after(function () {
    rmSync(dir, { recursive: true, force: true });
  });
  const run = (name: string, content: string | null) => {
    const path = join(dir, name);
    if (content !== null) writeFileSync(path, content);
    return spawnSync(process.execPath, ["--import", "tsx", "scripts/check-rustsec-drift.ts", "--live", path], {
      encoding: "utf8",
      env: { ...process.env, GITHUB_STEP_SUMMARY: "" },
    });
  };

  it("exits 0 on a match, 1 on drift, 2 on cleanup and 3 when unavailable", function () {
    const match = run("match.json", JSON.stringify(live()));
    expect(match.status, match.stderr).to.equal(0);
    expect(match.stdout).to.include("RustSec drift: MATCH");
    const drift = live();
    const twin = vuln(drift, "RUSTSEC-2026-0258");
    twin.advisory.id = "RUSTSEC-2099-0001";
    push(drift, twin);
    const red = run("drift.json", JSON.stringify(drift));
    expect(red.status).to.equal(1);
    expect(red.stdout).to.include("::error title=RustSec NEW_FINDING::");
    const gone = live();
    const v = audit(gone).vulnerabilities;
    v.list = v.list.filter((x: any) => x.advisory.id !== "RUSTSEC-2026-0285");
    v.count = v.list.length;
    const cleanup = run("cleanup.json", JSON.stringify(gone));
    expect(cleanup.status).to.equal(2);
    expect(cleanup.stdout).to.include("::warning title=RustSec DISAPPEARED::");
    expect(run("missing.json", null).status).to.equal(3);
    expect(run("garbage.json", "{ not json").status).to.equal(3);
  });

  it("exits 3 (unavailable), never 0, when it cannot run at all", function () {
    const r = spawnSync(process.execPath, ["--import", "tsx", "scripts/check-rustsec-drift.ts"], { encoding: "utf8" });
    expect(r.status).to.equal(3);
    expect(r.stderr).to.include("--live <observation.json> is required");
  });
});
