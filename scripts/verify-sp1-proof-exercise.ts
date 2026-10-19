/**
 * SP1-PA3B's verification of the exercise's proof through the designated verifier path (built by SP1-PA3A).
 *
 *   SP1_PROOF_EXERCISE_RUN=<committed run observation> SP1_PROOF_EXERCISE_HOST=<label> \
 *     SP1_PROOF_EXERCISE_OUT=<new file> npm run sp1:verify-proof-exercise
 *   add SP1_PROOF_EXERCISE_DEPLOYED=1 and `-- --network <name>` for a second check against the verifier deployed on
 *   that chain (the designation's CREATE2 address; the same code hash is required)
 *
 * The CREATE2-authenticated v6.1.0 runtime (SP1-TD1's initcode, its keccak the designation's) is deployed on the
 * development chain, its code hash measured, and `verifyProof` asked twice: the proof as the run observation holds
 * it, then its tampered copy. The verification observation binds the run observation's COMMITTED bytes (it must be
 * committed first) and is written once; `acceptance` is computed from the chain's answers, never set. A rejected
 * proof is recorded as such and exits non-zero. No chain is written to. Research prototype. Not audited.
 */
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { network } from "hardhat";

import { uncommittedEvidenceError } from "./lib/committed-evidence";
import { committedProductionAnchor } from "./lib/sp1-circuit-tooling";
import { latestDesignation, readDesignations } from "./lib/sp1-designation";
import {
  ACCEPTED,
  DEPLOYED_RUNTIME,
  LOCAL_RUNTIME,
  OBSERVATIONS_DIR,
  authenticatedInitcode,
  deployRuntime,
  scriptSha256Of,
  serializeJson,
  verificationObservationFor,
  verifyWithRuntime,
  type RunObservation,
  type VerificationCheck,
} from "./lib/sp1-proof-exercise";
import { runScript } from "./lib/run-script";
import { writeNewFiles } from "./lib/write-once";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (b: string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const runPath = env("SP1_PROOF_EXERCISE_RUN");
  const host = env("SP1_PROOF_EXERCISE_HOST");
  const out = env("SP1_PROOF_EXERCISE_OUT");
  const runRel = relative(realpathSync(REPO), realpathSync(runPath)).split(sep).join("/");
  if (!runRel.startsWith(`${OBSERVATIONS_DIR}/`)) throw new Error(`${runPath} is not under ${OBSERVATIONS_DIR}`);
  const dirty = uncommittedEvidenceError([runRel], REPO);
  if (dirty !== null)
    throw new Error(`the run observation is not as committed (this verification binds its committed bytes): ${dirty}`);
  const runText = lf(readFileSync(runPath, "utf8"));
  const run = JSON.parse(runText) as RunObservation;
  const designation = latestDesignation(readDesignations(REPO));
  if (!designation) throw new Error("no designation");
  const anchor = committedProductionAnchor(REPO);
  const proof = { programVKey: run.proof.vkey, publicValues: run.proof.publicValues, proofBytes: run.proof.proofBytes };

  const local = await network.create("default");
  const [deployer] = await local.ethers.getSigners();
  const address = await deployRuntime(deployer, authenticatedInitcode(REPO, designation));
  const checks: VerificationCheck[] = [
    await verifyWithRuntime(local.ethers.provider, { address, ...proof, mode: LOCAL_RUNTIME }),
  ];
  if (process.env.SP1_PROOF_EXERCISE_DEPLOYED === "1") {
    const deployed = await network.connect();
    checks.push(
      await verifyWithRuntime(deployed.ethers.provider, {
        address: designation.verifier.address,
        ...proof,
        mode: DEPLOYED_RUNTIME,
      }),
    );
  }
  const observation = verificationObservationFor({
    host,
    scriptSha256: scriptSha256Of(import.meta.url),
    run: { path: runRel, sha256: sha256(runText), observation: run },
    verifier: anchor.verifier,
    checks,
  });
  writeNewFiles([[resolve(out), serializeJson(observation)]], "a verification observation is never overwritten");
  console.log(
    `${out}: ${observation.acceptance} (${checks.map((c) => `chain ${c.chainId} ${c.mode}: ${c.verdicts.real} / tampered ${c.verdicts.tampered}`).join("; ")}). Commit it, then derive the record (npm run sp1:proof-exercise-record).`,
  );
  if (observation.acceptance !== ACCEPTED) process.exitCode = 1;
});
