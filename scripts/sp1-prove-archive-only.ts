/**
 * The archive-only Groth16 prove path (scripts/lib/sp1-prove-gate.ts), for designation d1.
 *
 *   npm run sp1:prove:archive-only -- --record <record.json> --circuit-root <absolute dir> \
 *     --host <absolute path to the built mldsa65-host> --inputs <absolute path to inputs.json> [--out <new file>]
 *
 * Runs `<host> prove <inputs>` only if the record is a production record accepted for d1, the caller's environment
 * selects nothing the gate does not freeze, the gnark image is in the local docker store by the record's digest, and
 * <circuit-root>/<circuit version> is, re-hashed now, exactly the record's members. Otherwise it refuses before the
 * host starts, so SP1 can never fall back to its own circuit download or a tagged image through this command. The
 * proof JSON goes to --out (created exclusively) or stdout. Never pulls an image or downloads anything itself.
 *
 * This lane generates no proof: no production record exists, so every run refuses. Research prototype. Not audited.
 */
import { readFileSync } from "node:fs";

import { refuse } from "./lib/sp1-circuit-archive";
import { authoritativeRecordError, productionAnchor } from "./lib/sp1-circuit-tooling";
import { dockerImageDigests, runArchiveOnlyProve, spawnHost } from "./lib/sp1-prove-gate";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

function arg(name: string, required = true): string | undefined {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (required && !value) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const recordPath = arg("--record") as string;
  const bad = authoritativeRecordError(recordPath, ".");
  if (bad) throw refuse("RECORD_NOT_AUTHORITATIVE", bad, `${recordPath} is not a production archive record`);
  const { plan, output } = await runArchiveOnlyProve(
    {
      record: JSON.parse(readFileSync(recordPath, "utf8")),
      anchor: productionAnchor("."),
      circuitRoot: arg("--circuit-root") as string,
      hostExecutable: arg("--host") as string,
      inputsPath: arg("--inputs") as string,
      callerEnv: process.env,
    },
    { images: dockerImageDigests, spawn: spawnHost },
  );
  if (plan.dropped.length > 0) console.error(`not passed to the host: ${plan.dropped.join(", ")}`);
  const json = `${JSON.stringify(output, null, 2)}\n`;
  const out = arg("--out", false);
  if (out) writeNewFiles([[out, json]], "the proof output is never overwritten");
  else process.stdout.write(json);
});
