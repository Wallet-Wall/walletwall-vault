/**
 * Derive (and validate) evidence/zk/sp1-impl/host-lockfile-advisories.json, the zkvm/host RustSec advisory record,
 * from the observation (scripts/measure-sp1-host-advisories.ts), the claims and the repository; see
 * scripts/lib/sp1-host-advisories.ts and docs/SP1_Host_Lockfile_Advisories.md.
 *
 *   npm run sp1:host-advisories            # write the record the evidence derives
 *   npm run validate:sp1-host-advisories   # offline check: observation, subject, assumptions, claims, record
 *
 * The check prints two verdicts and never folds one into the other: ASSESSMENT_VALID (the record is what today's
 * designated subject and evidence derive) and the dependency status (NOT_DEPENDENCY_SAFE while any RustSec
 * vulnerability or unsoundness is locked). It passes on ASSESSMENT_VALID alone, which says nothing is patched.
 *
 * No network, no cargo, no download. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  HOST_ADVISORIES_REL,
  advisoryStateFromRepo,
  deriveHostAdvisoryRecord,
  hostAdvisoryVerdict,
  serializeHostAdvisoryRecord,
  type HostAdvisoryRecord,
} from "./lib/sp1-host-advisories";

function summary(r: HostAdvisoryRecord): string[] {
  const c = r.assessment.counts;
  const k = c.byKind;
  return [
    `DEPENDENCY_STATUS: ${r.assessment.dependencyStatus}: zkvm/host/Cargo.lock locks ${k.vulnerability} RustSec vulnerabilities and ${k.unsound} unsound crates (+${k.yanked} yanked, ${k.unmaintained} unmaintained); ${r.remediation.status}, nothing is patched. A valid assessment is not a fix.`,
    `BUCKETS: MUST_FIX_BEFORE_REAL_PROVING ${r.buckets.MUST_FIX_BEFORE_REAL_PROVING.length} | SHOULD_FIX_BEFORE_PRODUCTION ${r.buckets.SHOULD_FIX_BEFORE_PRODUCTION.length} | NOT_REACHABLE_OR_UPSTREAM_ONLY ${r.buckets.NOT_REACHABLE_OR_UPSTREAM_ONLY.length} (${c.compiled} of ${c.findings} compiled)`,
    `COMPANIONS: ${r.companionLockfiles.map((x) => `${x.path} ${x.vulnerabilities} vulnerabilities, ${x.warnings} warnings`).join("; ")}`,
  ];
}

try {
  const state = advisoryStateFromRepo(".");
  if (process.argv.includes("--validate")) {
    const v = hostAdvisoryVerdict(state);
    if (v.assessment !== "ASSESSMENT_VALID") {
      throw new Error(
        `${v.assessment} (dependency status ${v.dependencyStatus}):\n - ${v.issues.map((i) => `[${i.code}] ${i.message}`).join("\n - ")}`,
      );
    }
    const r = v.derived as HostAdvisoryRecord;
    console.log(
      [
        `ASSESSMENT_VALID: ${HOST_ADVISORIES_REL} is what designation ${r.subject.designation.id}'s zkvm/host subject (HEAD tree ${r.subject.zkvmHostTree}), the observation (advisory-db ${r.assessment.database.lastCommit}) and the claims derive.`,
        ...summary(r),
      ].join("\n"),
    );
  } else {
    const record = deriveHostAdvisoryRecord(state);
    writeFileSync(resolve(HOST_ADVISORIES_REL), serializeHostAdvisoryRecord(record));
    console.log([`${HOST_ADVISORIES_REL} written.`, ...summary(record)].join("\n"));
    const pending = hostAdvisoryVerdict({ ...state, recordText: serializeHostAdvisoryRecord(record) }).issues;
    if (pending.length > 0) {
      console.log(`It does not validate yet:\n - ${pending.map((i) => `[${i.code}] ${i.message}`).join("\n - ")}`);
      process.exitCode = 1;
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
