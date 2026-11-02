/**
 * Author (and validate) evidence/zk/sp1-impl/pa3d-exercise-manifest.json, SP1-PA3D's exercise manifest, BEFORE the
 * one authorized proof; see scripts/lib/sp1-pa3d-exercise.ts.
 *
 *   npm run sp1:pa3d-manifest -- --source-commit <sha> --host-label <label> --environment-kind <kind> \
 *     --environment-description "<words>" --authorization-words "<the owner's words>" \
 *     --authorization-recorded-at <utc> [--started-at <utc>]      # write the manifest (never over an existing one)
 *   npm run validate:sp1-pa3d-manifest                             # it is what the checkout derives, here, now
 *
 * Everything but the operator's inputs is derived from the checkout: the designation, the archive record, the observer
 * qualification, SP1-PA3B's run (the expected public values), the canonical rebuild (host binary, toolchain), the
 * lockfiles, and the run tools as the source commit holds them. The validator re-derives the manifest from the inputs
 * the committed file carries and refuses any leaf that differs, a source commit the checkout does not descend from, a
 * tool the source commit holds differently (TOOL_DRIFT), or an observer that is not qualified for this lane. No proof,
 * no network, no docker, no kernel. PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED. Research prototype. Not audited.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runScript } from "./lib/run-script";
import {
  MANIFEST_REL,
  PRODUCTION_SP1_BINDING,
  manifestContextFromRepo,
  manifestErrors,
  manifestFrom,
  manifestInputsOf,
  serializeManifest,
  type ManifestInputs,
} from "./lib/sp1-pa3d-exercise";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));

function option(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function required(name: string): string {
  const v = option(name);
  if (v === undefined || v.startsWith("--") || v === "") throw new Error(`--${name} <value> is required`);
  return v;
}

const utcNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

runScript(async () => {
  const ctx = manifestContextFromRepo(REPO);
  if (process.argv.includes("--validate")) {
    const committedText = readFileSync(resolve(REPO, MANIFEST_REL), "utf8").replace(/\r\n/g, "\n");
    const committed: unknown = JSON.parse(committedText);
    const errors = manifestErrors(committed, ctx);
    const inputs = manifestInputsOf(committed);
    if (errors.length === 0 && inputs !== null && committedText !== serializeManifest(manifestFrom(ctx, inputs))) {
      errors.push("MANIFEST_BYTES_DIFFER: the committed text is not the derivation's serialization; regenerate it");
    }
    if (errors.length > 0) throw new Error(`the PA3D exercise manifest is invalid:\n - ${errors.join("\n - ")}`);
    const m = manifestFrom(ctx, inputs as ManifestInputs);
    console.log(
      `OK: ${MANIFEST_REL} is what the checkout derives from its operator inputs: source ${m.source.commit} (v${m.source.version}), ` +
        `${m.statement.designation} on ${m.environment.hostLabel}, ${m.artifacts.length} artifacts, acquisition gate ${m.acquisitionGate.verdict}, ` +
        `${m.authorization.proofs} proof authorized by the ${m.authorization.by}.`,
    );
    console.log(
      `PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING} (a manifest of an exercise; it binds nothing in production).`,
    );
    return;
  }
  const inputs: ManifestInputs = {
    sourceCommit: required("source-commit"),
    hostLabel: required("host-label"),
    environment: { kind: required("environment-kind"), description: required("environment-description") },
    startedAtUtc: option("started-at") ?? utcNow(),
    authorization: {
      by: "OWNER",
      proofs: 1,
      words: required("authorization-words"),
      recordedAtUtc: required("authorization-recorded-at"),
    },
  };
  const manifest = manifestFrom(ctx, inputs);
  writeNewFiles(
    [[resolve(REPO, MANIFEST_REL), serializeManifest(manifest)]],
    "an exercise manifest is never overwritten",
  );
  console.log(
    `${MANIFEST_REL}: source ${manifest.source.commit} (v${manifest.source.version}), ${manifest.artifacts.length} artifacts, ` +
      `acquisition gate ${manifest.acquisitionGate.verdict}, started ${manifest.startedAtUtc}.`,
  );
  console.log(`PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING}.`);
});
