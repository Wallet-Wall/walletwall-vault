/**
 * Generate (and validate) SP1 program designations in evidence/zk/sp1/designations/; see
 * scripts/lib/sp1-designation.ts.
 *
 * Usage:
 *   npm run sp1:designation              # write mldsa65-withdrawal-d1 from SP1-TD1's evidence if it is not there yet
 *   npm run validate:sp1-designation     # regenerate and compare, check the subject, the set and verifier drift
 *   npm run sp1:designation -- --successor <bundle.json>
 *                                        # derive the next designation from an evidence bundle (it names the
 *                                        # predecessor and the reason); writes the designation and keeps the bundle
 *
 * A designation is written once and never rewritten (the append-only history check keeps it that way). No
 * transactions, no deploys, no network. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DESIGNATIONS_DIR,
  DESIGNATION_EVIDENCE_DIR,
  deriveInitialDesignation,
  deriveSuccessorDesignation,
  designationSetErrors,
  type DesignationEvidenceBundle,
  readDesignations,
  serializeDesignation,
  validateDesignationsInRepo,
} from "./lib/sp1-designation";
import { readDecisionContext } from "./lib/sp1-td1-decision";
import { writeNewFiles } from "./lib/write-once";

function generateInitial(): void {
  const existing = readDesignations();
  if (existing.length > 0) {
    const errors = validateDesignationsInRepo();
    if (errors.length > 0) throw new Error(`the committed designations are invalid:\n - ${errors.join("\n - ")}`);
    console.log(`unchanged: ${existing.map((d) => d.id).join(", ")} (a designation is never rewritten)`);
    return;
  }
  const d1 = deriveInitialDesignation(readDecisionContext());
  mkdirSync(resolve(DESIGNATIONS_DIR), { recursive: true });
  const path = resolve(DESIGNATIONS_DIR, `${d1.id}.json`);
  writeNewFiles([[path, serializeDesignation(d1)]], "a designation is never rewritten");
  console.log(`designated ${d1.id}: PROGRAM_VKEY ${d1.programVKey}, identity ${d1.identity}`);
}

function generateSuccessor(bundlePath: string): void {
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8")) as DesignationEvidenceBundle;
  const set = readDesignations();
  const errors = designationSetErrors(set);
  if (errors.length > 0) throw new Error(`the committed designations are invalid:\n - ${errors.join("\n - ")}`);
  const next = deriveSuccessorDesignation(bundle, set);
  const designationPath = resolve(DESIGNATIONS_DIR, `${next.id}.json`);
  const bundleOut = resolve(DESIGNATION_EVIDENCE_DIR, `${next.id}.json`);
  mkdirSync(resolve(DESIGNATION_EVIDENCE_DIR), { recursive: true });
  writeNewFiles(
    [
      [bundleOut, `${JSON.stringify(bundle, null, 2)}\n`],
      [designationPath, serializeDesignation(next)],
    ],
    "a designation and its evidence are never rewritten",
  );
  console.log(
    `designated ${next.id} (succeeds ${String(next.predecessor?.id)}): PROGRAM_VKEY ${next.programVKey}, identity ${next.identity}`,
  );
}

function validate(): void {
  const errors = validateDesignationsInRepo();
  if (errors.length > 0) throw new Error(`the SP1 designations are invalid:\n - ${errors.join("\n - ")}`);
  console.log(
    `OK: ${readDesignations()
      .map((d) => d.id)
      .join(
        ", ",
      )} regenerate from evidence, the zkvm subject is the latest designation's, and the compiled wrapper's verifier is designated.`,
  );
}

try {
  const successor = process.argv.indexOf("--successor");
  if (process.argv.includes("--validate")) validate();
  else if (successor !== -1) generateSuccessor(String(process.argv[successor + 1]));
  else generateInitial();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
