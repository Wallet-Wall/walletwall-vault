/**
 * Hosted PQ verifier DEMO runner — SPIKE ONLY.
 *
 * ⚠️ Non-production spike. This does NOT start a server or open a network
 * listener. It feeds the committed library-generated ML-DSA-65 fixture (and a
 * tampered copy) through the in-process {@link handleHostedVerifyRequest} and
 * prints the deterministic responses, so the request/response shape of a future
 * hosted verifier is tangible without deploying anything.
 *
 * Run: npm run hosted:demo
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { hexlify, getBytes } from "ethers";

import { handleHostedVerifyRequest } from "./lib/hosted-verifier-demo";

const FIXTURE_DIR = resolve("test/fixtures/mldsa/library-generated");
const readHex = (name: string): string => readFileSync(join(FIXTURE_DIR, name), "utf8").trim();

/** Fixed instant so the demo output is reproducible. */
const DEMO_NOW = "2026-01-01T00:00:00.000Z";

function main(): void {
  const message = readHex("message.hex");
  const publicKey = readHex("public-key.hex");
  const signature = readHex("signature.hex");

  console.log("# Hosted PQ verifier demo (SPIKE — no server, no secrets, no signing)\n");

  const valid = handleHostedVerifyRequest(
    { message, publicKey, signature, source: { type: "library-generated", reference: "library-generated/ml-dsa-65" } },
    { now: DEMO_NOW },
  );
  console.log("## valid request →");
  console.log(JSON.stringify(valid, null, 2));

  // Tamper one signature byte to show a failed verification is still a 200 OK
  // response carrying evidence with verified:false.
  const tampered = getBytes(signature);
  tampered[0] ^= 0x01;
  const failed = handleHostedVerifyRequest({ message, publicKey, signature: hexlify(tampered) }, { now: DEMO_NOW });
  console.log("\n## tampered-signature request →");
  console.log(JSON.stringify(failed, null, 2));

  // A malformed request is the only non-2xx path (here: odd-length hex → 400).
  const malformed = handleHostedVerifyRequest({ message: "0xabc", publicKey, signature }, { now: DEMO_NOW });
  console.log("\n## malformed request →");
  console.log(JSON.stringify(malformed, null, 2));
}

if (process.argv[1]?.includes("hosted-verifier-demo")) {
  main();
}
