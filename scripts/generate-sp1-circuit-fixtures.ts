/**
 * Writes SP1-PA2A's synthetic fixtures (scripts/lib/sp1-circuit-fixtures.ts) to test/fixtures/sp1-proving-archives:
 * the synthetic anchor, the safe synthetic archive and its record. They are test data only: the anchor names no
 * designation, and the production anchor refuses the record (`npm run validate:sp1-circuit-tooling` proves it).
 *
 *   npx tsx scripts/generate-sp1-circuit-fixtures.ts
 *
 * The tar stream is deterministic; its gzip bytes are this zlib's, and the record is derived from them, so
 * regenerating on another platform may change both together. Research prototype. Not audited.
 */
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  SAFE_ARCHIVE_REL,
  SAFE_FILES,
  SAFE_RECORD_REL,
  SYNTHETIC_ANCHOR,
  SYNTHETIC_ANCHOR_REL,
  gz,
  safeTar,
  syntheticRecord,
} from "./lib/sp1-circuit-fixtures";

const archive = gz(safeTar());
writeFileSync(resolve(SAFE_ARCHIVE_REL), archive);
writeFileSync(resolve(SAFE_RECORD_REL), `${JSON.stringify(syntheticRecord(archive, SAFE_FILES), null, 2)}\n`);
writeFileSync(
  resolve(SYNTHETIC_ANCHOR_REL),
  `${JSON.stringify(
    {
      synthetic: true,
      note: "SP1-PA2A test fixture. Not a designation, not a verifying key, never evidence of proving availability.",
      anchor: SYNTHETIC_ANCHOR,
    },
    null,
    2,
  )}\n`,
);
console.log(`${SAFE_ARCHIVE_REL}, ${SAFE_RECORD_REL}, ${SYNTHETIC_ANCHOR_REL}`);
