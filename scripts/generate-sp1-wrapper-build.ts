/**
 * Record (and validate) builds of the ZKMLDSAVerifier wrapper in evidence/zk/sp1/wrapper-builds/; see
 * scripts/lib/sp1-wrapper-build.ts.
 *
 * Usage (both compile first):
 *   npm run sp1:wrapper-build            # append a record when the compiled wrapper is not the latest recorded build
 *   npm run validate:sp1-wrapper-build   # fail unless the compiled wrapper is the latest recorded build
 *
 * A record is written once and never edited; the append-only history check keeps it that way. No transactions, no
 * deploys, no network. Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  WRAPPER_BUILDS_DIR,
  buildFromCompilation,
  currentBuildErrors,
  nextBuildRecord,
  readWrapperBuilds,
  serializeBuild,
  wrapperBuildErrors,
} from "./lib/sp1-wrapper-build";

function record(): void {
  const builds = readWrapperBuilds();
  const errors = wrapperBuildErrors(builds);
  if (errors.length > 0) throw new Error(`the recorded wrapper builds are invalid:\n - ${errors.join("\n - ")}`);
  const next = nextBuildRecord(buildFromCompilation(), builds);
  if (next === null) {
    console.log(`unchanged: the compiled wrapper is ${builds[builds.length - 1].id}`);
    return;
  }
  const path = resolve(WRAPPER_BUILDS_DIR, `${next.id}.json`);
  if (existsSync(path)) throw new Error(`${path} exists: a recorded build is never rewritten`);
  writeFileSync(path, serializeBuild(next));
  console.log(`recorded ${next.id} (${next.runtime.bytes} runtime bytes, ${next.runtime.templateKeccak})`);
}

function validate(): void {
  const errors = currentBuildErrors();
  if (errors.length > 0) throw new Error(`the wrapper build records do not match:\n - ${errors.join("\n - ")}`);
  const builds = readWrapperBuilds();
  console.log(`OK: the compiled ZKMLDSAVerifier is the latest recorded build, ${builds[builds.length - 1].id}.`);
}

try {
  if (process.argv.includes("--validate")) validate();
  else record();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
