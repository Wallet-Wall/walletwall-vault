/**
 * Measures, read-only and offline, what the SP1 crates zkvm/host/Cargo.lock pins do with the Groth16 circuit
 * directory, the gnark image and the prover mode, and every environment variable they read
 * (scripts/lib/sp1-circuit-tooling.ts), and writes the observation the circuit-tooling record is derived from.
 *
 *   npx tsx scripts/measure-sp1-circuit-upstream.ts --cargo-home <dir> [--host <id>]
 *
 *   --cargo-home  a CARGO_HOME whose registry cache holds every sp1-* and slop-* crate the host lockfile pins; each
 *                 cached copy must have the lockfile's checksum, and sources are read from those bytes only
 *
 * It downloads nothing and writes only the observation. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { UPSTREAM_OBSERVATION_REL, UPSTREAM_SCRIPT_REL, measureUpstream } from "./lib/sp1-circuit-tooling";

function arg(name: string): string {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

try {
  const host = process.argv.includes("--host") ? arg("--host") : "developer-workstation";
  if (host !== "developer-workstation") throw new Error(`the committed observation is ${UPSTREAM_OBSERVATION_REL}`);
  const obs = measureUpstream({
    repoRoot: ".",
    cargoHome: arg("--cargo-home"),
    host,
    measuredAtUtc: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    tool: {
      script: UPSTREAM_SCRIPT_REL,
      scriptSha256: createHash("sha256")
        .update(readFileSync(resolve(UPSTREAM_SCRIPT_REL)))
        .digest("hex"),
    },
  });
  writeFileSync(resolve(UPSTREAM_OBSERVATION_REL), `${JSON.stringify(obs, null, 2)}\n`);
  console.log(
    `${UPSTREAM_OBSERVATION_REL}: ${obs.crates.length} crates, ${Object.keys(obs.environment).length} environment ` +
      `variables, circuit ${obs.facts.circuitVersion}, ${obs.nonLiteralEnvironmentReads.length} non-literal reads`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
