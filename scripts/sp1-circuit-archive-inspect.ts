/**
 * Inspects an SP1 Groth16 circuit archive offline (scripts/lib/sp1-circuit-archive.ts), against designation d1.
 *
 *   npm run sp1:circuit-archive:inspect -- --archive <file.tar.gz> [--record <record.json>]
 *
 * With --record: the record must be accepted for d1, the archive's sha256 and length must be the record's before any
 * byte is parsed, every entry must pass the path and type rules, and the members must be exactly the record's.
 * Without it (measuring a candidate for a future record): the entry rules still apply, the files SP1 reads must be
 * present, and groth16_vk.bin must be d1's verifying key. Prints the measurement as JSON; refuses with exit 1.
 *
 * Reads only the archive: no network, no download, no SP1, no tar(1). Research prototype. Not audited.
 */
import { readFileSync } from "node:fs";

import { inspectArchive } from "./lib/sp1-circuit-archive";
import { productionAnchor } from "./lib/sp1-circuit-tooling";
import { runScript } from "./lib/run-script";

function arg(name: string, required = true): string | undefined {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (required && !value) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const anchor = productionAnchor(".");
  const recordPath = arg("--record", false);
  const record = recordPath === undefined ? undefined : JSON.parse(readFileSync(recordPath, "utf8"));
  const inspection = await inspectArchive(arg("--archive") as string, { anchor, record });
  console.log(JSON.stringify({ designation: anchor.designation, ...inspection }, null, 2));
});
