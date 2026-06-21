/**
 * Standalone open PQ verifier CLI.
 *
 * Answers only: "Did this ML-DSA-65 signature verify for this message and
 * public key?" and prints a deterministic structured result.
 *
 * It NEVER signs anything, NEVER reads ATTESTOR_PRIVATE_KEY, and NEVER builds an
 * EIP-712 attestation. A failed verification is still a successful process
 * (exit 0) reporting `verified: false`; only malformed CLI input exits non-zero.
 *
 *   npm run verifier:verify -- \
 *     --message 0x... --public-key 0x... --pq-signature 0x... --json
 *
 *   npm run verifier:verify -- \
 *     --message-file ./message.bin \
 *     --public-key-file ./public-key.bin \
 *     --pq-signature-file ./signature.bin --json
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import type { PQVerificationResult } from "../src/verifier/ml-dsa-65";
// @ts-expect-error ts-node ESM requires the explicit extension.
import { verifyMLDSA65Detailed } from "../src/verifier/ml-dsa-65.ts";
// @ts-expect-error ts-node ESM requires the explicit extension.
import { readBytesInput } from "./lib/attestation.ts";

interface ParsedVerifierArgs {
  command: string;
  json: boolean;
  values: Map<string, string>;
}

export function parseVerifierArgs(args: string[]): ParsedVerifierArgs {
  const command = args[0] ?? "verify";
  if (command !== "verify") {
    throw new Error(`Unknown command "${command}". Supported command: verify`);
  }

  const values = new Map<string, string>();
  let json = false;
  let i = 1;
  while (i < args.length) {
    const flag = args[i];
    if (!flag?.startsWith("--")) {
      throw new Error(`Expected a --flag but found "${flag ?? "<end>"}"`);
    }
    if (flag === "--json") {
      json = true;
      i += 1;
      continue;
    }
    const value = args[i + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for ${flag}`);
    }
    values.set(flag.slice(2), value);
    i += 2;
  }

  return { command, json, values };
}

export function runVerify(parsed: ParsedVerifierArgs): PQVerificationResult {
  const message = readBytesInput(parsed.values.get("message"), parsed.values.get("message-file"), "message");
  const publicKey = readBytesInput(parsed.values.get("public-key"), parsed.values.get("public-key-file"), "public-key");
  const signature = readBytesInput(
    parsed.values.get("pq-signature"),
    parsed.values.get("pq-signature-file"),
    "pq-signature",
  );

  return verifyMLDSA65Detailed(publicKey, message, signature);
}

function printHuman(result: PQVerificationResult): void {
  console.log(`verifier:      ${result.verifier.name}@${result.verifier.version}`);
  console.log(`algorithm:     ${result.algorithm} (${result.fips}, mode=${result.mode})`);
  console.log(`messageHash:   ${result.input.messageHash}`);
  console.log(`publicKeyHash: ${result.input.publicKeyHash}`);
  console.log(`signatureHash: ${result.input.signatureHash}`);
  console.log(`verified:      ${result.result.verified}`);
  console.log(`reason:        ${result.result.reason}`);
}

export function main(args = process.argv.slice(2)): PQVerificationResult {
  const parsed = parseVerifierArgs(args);
  const result = runVerify(parsed);

  if (parsed.json) {
    // --json prints JSON only.
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHuman(result);
  }

  return result;
}

// Only execute when invoked directly (e.g. `npm run verifier:verify`), not when
// imported by tests. This guard works under both the ESM CLI runtime and the
// CommonJS test runtime without relying on import.meta or require.main.
if (process.argv[1]?.includes("pq-verifier-cli")) {
  try {
    main();
  } catch (error) {
    // Malformed CLI input is the only non-zero exit path.
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
