/**
 * Validate SP1-PA3E's production-binding design manifest and document against each other and against the spec's
 * requirements; see scripts/lib/sp1-pa3e-design.ts.
 *
 *   npm run validate:sp1-pa3e-design
 *
 * Checks: the manifest is internally consistent (designErrors), the document states every identifier the manifest
 * declares together with the lane's state and the binding status (designDocErrors), the manifest's top-level keys are
 * exactly the JSON schema's required properties, and the PA3D record the manifest names is the committed one (by
 * digest and state). No proof, no network, no chain, no contract. A design is validated, not a binding:
 * PRODUCTION_SP1_BINDING stays NOT_ESTABLISHED. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runScript } from "./lib/run-script";
import {
  DESIGN_DOC_REL,
  DESIGN_JSON_SCHEMA_REL,
  DESIGN_REL,
  PRODUCTION_SP1_BINDING,
  baselineErrors,
  designDocErrors,
  designErrors,
  type DesignManifest,
} from "./lib/sp1-pa3e-design";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const read = (rel: string) => lf(readFileSync(resolve(REPO, rel), "utf8"));

runScript(async () => {
  const manifest = JSON.parse(read(DESIGN_REL)) as DesignManifest;
  const errors = designErrors(manifest);

  const schema = JSON.parse(read(DESIGN_JSON_SCHEMA_REL)) as {
    required: string[];
    properties: Record<string, unknown>;
  };
  const keys = Object.keys(manifest).sort().join(",");
  if (keys !== [...schema.required].sort().join(","))
    errors.push("SCHEMA_KEYS: the manifest's keys are not the schema's required properties");
  if (Object.keys(schema.properties).sort().join(",") !== [...schema.required].sort().join(",")) {
    errors.push("SCHEMA_PROPERTIES: the schema's properties are not its required list");
  }

  const recordText = read(manifest.evidenceBaseline.pa3dRecord.path);
  const recordSha = createHash("sha256").update(recordText).digest("hex");
  if (recordSha !== manifest.evidenceBaseline.pa3dRecord.sha256) {
    errors.push(
      `BASELINE_RECORD_DIGEST: committed PA3D record is ${recordSha}, manifest names ${manifest.evidenceBaseline.pa3dRecord.sha256}`,
    );
  }
  const pkg = JSON.parse(read("package.json")) as { version: string };
  errors.push(...baselineErrors(manifest, JSON.parse(recordText), pkg.version));

  errors.push(...designDocErrors(manifest, read(DESIGN_DOC_REL)));

  if (errors.length > 0) throw new Error(`the PA3E design is invalid:\n - ${errors.join("\n - ")}`);
  const open = manifest.threats.filter((t) => t.status !== "RESOLVED");
  console.log(
    `OK: ${DESIGN_REL} and ${DESIGN_DOC_REL} agree: ${manifest.state}; ${manifest.threats.length} threats ` +
      `(${manifest.threats.length - open.length} resolved, ${open.map((t) => `${t.id} ${t.status}`).join(", ")}); ` +
      `${manifest.invariants.length} invariants; ${manifest.residues.length} PA3D residues adjudicated; ` +
      `${manifest.gates.length} gates; recommended Candidate ${manifest.recommended.candidate}; ` +
      `${manifest.unresolved.length} open questions, ${manifest.unresolved.filter((u) => u.blocking).length} blocking.`,
  );
  console.log(`PRODUCTION_SP1_BINDING = ${PRODUCTION_SP1_BINDING} (a design, not a binding).`);
});
