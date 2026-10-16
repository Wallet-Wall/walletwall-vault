/**
 * Measures, read-only, what proving availability (SP1-TD1 finding TD1-N9) can establish without the circuit
 * artifacts (scripts/lib/sp1-proving-availability.ts), and writes the observation.
 *
 *   npx tsx scripts/measure-sp1-proving-artifacts.ts --cargo-home <dir> --home <dir> --cargo-tree <file> [--host <id>]
 *
 *   --cargo-home  the proving host's CARGO_HOME, whose registry cache holds the crates zkvm/host/Cargo.lock pins
 *   --home        the proving host's home directory, where the pinned prover installs the artifacts
 *   --cargo-tree  the output of `cargo tree --offline --locked -e features -i sp1-recursion-gnark-ffi`, run in
 *                 zkvm/host on that host
 *
 * The local gnark images are read with the docker CLI; a docker that does not answer fails the measurement (unmeasured
 * is not absent). It downloads nothing and writes only the observation. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { GNARK_TREE_COMMAND, MEASURE_SCRIPT_REL, measureProvingArtifacts } from "./lib/sp1-proving-availability";

function arg(name: string): string {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function localImages(repository: string): string[] {
  const r = spawnSync(
    "docker",
    ["image", "ls", "--no-trunc", "--format", "{{.Repository}}:{{.Tag}} {{.ID}} {{.Digest}}", repository],
    { encoding: "utf8" },
  );
  if (r.status !== 0)
    throw new Error(`docker did not answer (${String(r.stderr || r.error)}): the local images are unmeasured`);
  return r.stdout.split(/\r?\n/).filter((l) => l.trim() !== "");
}

try {
  const host = process.argv.includes("--host") ? arg("--host") : "developer-workstation";
  const obs = measureProvingArtifacts({
    repoRoot: ".",
    cargoHome: arg("--cargo-home"),
    home: arg("--home"),
    hostId: host,
    cargoTree: { command: GNARK_TREE_COMMAND, output: readFileSync(arg("--cargo-tree"), "utf8") },
    localImages,
    measuredAtUtc: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    tool: {
      script: MEASURE_SCRIPT_REL,
      scriptSha256: createHash("sha256")
        .update(readFileSync(resolve(MEASURE_SCRIPT_REL)))
        .digest("hex"),
    },
  });
  const out = `evidence/zk/sp1-impl/observations/proving-artifacts-${host}.raw.json`;
  writeFileSync(resolve(out), `${JSON.stringify(obs, null, 2)}\n`);
  console.log(
    `${out}: circuit ${obs.source.circuitVersion}, groth16_vk.bin sha256 ${obs.source.groth16Vk.sha256}, ` +
      `gnark ${obs.gnark.backend}, local artifacts ${obs.local.groth16DirPresent ? "present" : "absent"}`,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
