/**
 * The archive-only Groth16 prove path (scripts/lib/sp1-prove-gate.ts), for designation d1.
 *
 *   npm run sp1:prove:archive-only -- --record <record.json> --circuit-root <absolute dir> \
 *     --host <absolute path to the built mldsa65-host> --inputs <absolute path to inputs.json> [--out <new file>]
 *
 * Runs `<host> prove <inputs>` only if the record is a production record, exactly as committed and accepted for d1
 * (whose committed evidence is read from the checkout this script lives in, never the working directory); the
 * caller's environment selects nothing the gate does not freeze; the gnark image is in the local docker store by the
 * record's digest; and <circuit-root> holds only <circuit version>, which, re-hashed now, is exactly the record's
 * members. The root is then locked read-only for the run (POSIX, unprivileged user only). Otherwise it refuses before
 * the host starts, so SP1 can never fall back to its own circuit download or a tagged image through this command. The
 * proof JSON goes to --out (created exclusively) or stdout. Never pulls an image or downloads anything itself.
 *
 * This lane generates no proof: no production record exists, so every run refuses. Research prototype. Not audited.
 */
import { fileURLToPath } from "node:url";

import { committedProductionAnchor, committedProductionRecord } from "./lib/sp1-circuit-tooling";
import { dockerImageDigests, runArchiveOnlyProve, spawnHost } from "./lib/sp1-prove-gate";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));

function arg(name: string, required = true): string | undefined {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (required && !value) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const record = committedProductionRecord(arg("--record") as string, REPO);
  const { plan, output } = await runArchiveOnlyProve(
    {
      record,
      anchor: committedProductionAnchor(REPO),
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
