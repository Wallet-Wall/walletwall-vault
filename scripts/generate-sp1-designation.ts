/**
 * Generate (and validate) SP1 program designations in evidence/zk/sp1/designations/; see
 * scripts/lib/sp1-designation.ts.
 *
 * Usage:
 *   npm run sp1:designation              # write mldsa65-withdrawal-d1 from SP1-TD1's evidence if it is not there yet
 *   npm run validate:sp1-designation     # regenerate and compare, check the subject, the set and verifier drift
 *
 * A designation is written once and never rewritten (the append-only history check keeps it that way). No
 * transactions, no deploys, no network. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DESIGNATIONS_DIR,
  deriveInitialDesignation,
  readDesignations,
  serializeDesignation,
  validateDesignationsInRepo,
} from "./lib/sp1-designation";
import { readDecisionContext } from "./lib/sp1-td1-decision";

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
  if (existsSync(path)) throw new Error(`${path} exists: a designation is never rewritten`);
  writeFileSync(path, serializeDesignation(d1));
  console.log(`designated ${d1.id}: PROGRAM_VKEY ${d1.programVKey}, identity ${d1.identity}`);
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
  if (process.argv.includes("--validate")) validate();
  else generateInitial();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
