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
  recordSummary,
  serializeHostAdvisoryRecord,
  validationReport,
} from "./lib/sp1-host-advisories";

try {
  const state = advisoryStateFromRepo(".");
  if (process.argv.includes("--validate")) {
    const report = validationReport(hostAdvisoryVerdict(state));
    (report.pass ? console.log : console.error)(report.lines.join("\n"));
    if (!report.pass) process.exitCode = 1;
  } else {
    const record = deriveHostAdvisoryRecord(state);
    writeFileSync(resolve(HOST_ADVISORIES_REL), serializeHostAdvisoryRecord(record));
    console.log([`${HOST_ADVISORIES_REL} written.`, ...recordSummary(record)].join("\n"));
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
