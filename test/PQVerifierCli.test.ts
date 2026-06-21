/**
 * Tests for the standalone open PQ verifier CLI.
 *
 * These run the CLI's exported entry points in-process under the same runtime
 * as the rest of the suite, so they are robust across Node versions and CI. The
 * CLI's auto-run block is guarded by a process.argv check, so importing it here
 * does not execute it. Exit-code semantics are represented by throw / no-throw:
 * the auto-run wrapper turns a thrown error into a non-zero exit and a clean
 * return into exit 0.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect } from "chai";

import { main, parseVerifierArgs, runVerify } from "../scripts/pq-verifier-cli";

const fixtureDir = resolve("test/fixtures/mldsa/library-generated");
const messageFile = join(fixtureDir, "message.hex");
const publicKeyFile = join(fixtureDir, "public-key.hex");
const signatureFile = join(fixtureDir, "signature.hex");

const messageHex = readFileSync(messageFile, "utf8").trim();
const publicKeyHex = readFileSync(publicKeyFile, "utf8").trim();
const signatureHex = readFileSync(signatureFile, "utf8").trim();

function fileArgs(): string[] {
  return [
    "verify",
    "--message-file",
    messageFile,
    "--public-key-file",
    publicKeyFile,
    "--pq-signature-file",
    signatureFile,
  ];
}

/** Capture console.log output produced while running `fn`. */
function captureLog(fn: () => void): string {
  const lines: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map((a) => String(a)).join(" "));
  };
  try {
    fn();
  } finally {
    console.log = original;
  }
  return lines.join("\n");
}

describe("Open PQ verifier CLI (verifier:verify)", function () {
  it("verifies a valid triple from hex files", function () {
    const result = runVerify(parseVerifierArgs(fileArgs()));
    expect(result.result.verified).to.equal(true);
    expect(result.result.reason).to.equal("ML_DSA_65_VALID");
    expect(result.schemaVersion).to.equal("walletwall.pq-verifier.v1");
    expect(result.mode).to.equal("pure");
  });

  it("verifies the same triple from inline hex", function () {
    const result = runVerify(
      parseVerifierArgs([
        "verify",
        "--message",
        messageHex,
        "--public-key",
        publicKeyHex,
        "--pq-signature",
        signatureHex,
      ]),
    );
    expect(result.result.verified).to.equal(true);
  });

  it("treats non-hex files as raw bytes", function () {
    const dir = mkdtempSync(join(tmpdir(), "pqverifier-"));
    const rawMessage = join(dir, "message.bin");
    const rawPublicKey = join(dir, "public-key.bin");
    const rawSignature = join(dir, "signature.bin");
    writeFileSync(rawMessage, Buffer.from(messageHex.slice(2), "hex"));
    writeFileSync(rawPublicKey, Buffer.from(publicKeyHex.slice(2), "hex"));
    writeFileSync(rawSignature, Buffer.from(signatureHex.slice(2), "hex"));

    const result = runVerify(
      parseVerifierArgs([
        "verify",
        "--message-file",
        rawMessage,
        "--public-key-file",
        rawPublicKey,
        "--pq-signature-file",
        rawSignature,
      ]),
    );
    expect(result.result.verified).to.equal(true);
  });

  it("reports a failed verification as a non-error (verified false, no throw)", function () {
    const tamperedSig = "0x" + (signatureHex[2] === "0" ? "1" : "0") + signatureHex.slice(3);
    let result: ReturnType<typeof runVerify> | undefined;
    expect(() => {
      result = runVerify(
        parseVerifierArgs([
          "verify",
          "--message",
          messageHex,
          "--public-key",
          publicKeyHex,
          "--pq-signature",
          tamperedSig,
        ]),
      );
    }).to.not.throw();
    expect(result!.result.verified).to.equal(false);
  });

  it("does not require ATTESTOR_PRIVATE_KEY", function () {
    const original = process.env.ATTESTOR_PRIVATE_KEY;
    delete process.env.ATTESTOR_PRIVATE_KEY;
    try {
      const result = runVerify(parseVerifierArgs(fileArgs()));
      expect(result.result.verified).to.equal(true);
    } finally {
      if (original !== undefined) process.env.ATTESTOR_PRIVATE_KEY = original;
    }
  });

  it("--json prints JSON only, with no raw key/signature material", function () {
    const args = [...fileArgs().slice(1), "--json"]; // drop leading "verify" for main()
    const output = captureLog(() => main(["verify", ...args]));
    const parsed = JSON.parse(output);
    expect(parsed.result.verified).to.equal(true);
    expect(parsed.result.reason).to.equal("ML_DSA_65_VALID");
    expect(output).to.not.include(publicKeyHex.slice(2));
    expect(output).to.not.include(signatureHex.slice(2));
  });

  it("prints a concise human-readable result without --json", function () {
    const output = captureLog(() => main(fileArgs()));
    expect(output).to.include("verified:      true");
    expect(output).to.include("reason:        ML_DSA_65_VALID");
  });

  it("throws (non-zero exit) when an input has both inline and file forms", function () {
    expect(() =>
      main([
        "verify",
        "--message",
        messageHex,
        "--message-file",
        messageFile,
        "--public-key-file",
        publicKeyFile,
        "--pq-signature-file",
        signatureFile,
      ]),
    ).to.throw(/exactly one/i);
  });

  it("throws (non-zero exit) when a required input is missing", function () {
    expect(() => main(["verify", "--message-file", messageFile])).to.throw();
  });

  it("throws (non-zero exit) on an unknown command", function () {
    expect(() => parseVerifierArgs(["bogus"])).to.throw(/unknown command/i);
  });

  it("throws (non-zero exit) on malformed inline hex (non-hex characters)", function () {
    expect(() =>
      main(["verify", "--message", "0xZZZZ", "--public-key", publicKeyHex, "--pq-signature", signatureHex]),
    ).to.throw(/hex/i);
  });

  it("throws (non-zero exit) on malformed inline hex (odd length)", function () {
    // Odd-length hex is rejected before verification; the exact message comes from
    // the hex decoder, so we only assert that it exits non-zero (throws).
    expect(() =>
      main(["verify", "--message", "0x123", "--public-key", publicKeyHex, "--pq-signature", signatureHex]),
    ).to.throw();
  });

  it("rejects inline values without a 0x prefix (no base64 inline form)", function () {
    // Inline inputs are 0x-prefixed hex only; an un-prefixed/base64-looking value
    // is rejected rather than silently misinterpreted. Raw-byte files remain the
    // way to pass non-hex material (covered above).
    expect(() =>
      main(["verify", "--message", "aGVsbG8=", "--public-key", publicKeyHex, "--pq-signature", signatureHex]),
    ).to.throw(/hex/i);
  });
});
