/**
 * End-to-end tests for the standalone open PQ verifier CLI.
 *
 * These spawn the real `verifier:verify` command the same way the npm script
 * does (ts-node --esm), so they exercise the actual shipped process: argument
 * parsing, inline-hex vs file vs raw-binary inputs, --json output, exit codes,
 * and the guarantee that the CLI needs no ATTESTOR_PRIVATE_KEY and never prints
 * raw key/signature material.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect } from "chai";

const TS_NODE_BIN = require.resolve("ts-node/dist/bin.js");
const CLI = resolve("scripts/pq-verifier-cli.ts");

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], env?: NodeJS.ProcessEnv): CliResult {
  const result = spawnSync(process.execPath, [TS_NODE_BIN, "--esm", CLI, "verify", ...args], {
    encoding: "utf8",
    env: env ?? process.env,
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

// Library-generated fixture: a valid (message, publicKey, signature) triple whose
// .hex files are committed with 0x-prefixed values for direct CLI validation.
const fixtureDir = resolve("test/fixtures/mldsa/library-generated");
const messageFile = join(fixtureDir, "message.hex");
const publicKeyFile = join(fixtureDir, "public-key.hex");
const signatureFile = join(fixtureDir, "signature.hex");

function readHex(path: string): string {
  return readFileSync(path, "utf8").trim();
}

describe("Open PQ verifier CLI (verifier:verify)", function () {
  // ts-node cold start per spawn; give the suite generous headroom.
  this.timeout(120_000);

  const messageHex = readHex(messageFile);
  const publicKeyHex = readHex(publicKeyFile);
  const signatureHex = readHex(signatureFile);

  it("verifies a valid triple from hex files and prints JSON only", function () {
    const { status, stdout } = runCli([
      "--message-file",
      messageFile,
      "--public-key-file",
      publicKeyFile,
      "--pq-signature-file",
      signatureFile,
      "--json",
    ]);

    expect(status).to.equal(0);
    const parsed = JSON.parse(stdout);
    expect(parsed.result.verified).to.equal(true);
    expect(parsed.result.reason).to.equal("ML_DSA_65_VALID");
    expect(parsed.schemaVersion).to.equal("walletwall.pq-verifier.v1");
    expect(parsed.mode).to.equal("pure");
  });

  it("verifies the same triple from inline hex", function () {
    const { status, stdout } = runCli([
      "--message",
      messageHex,
      "--public-key",
      publicKeyHex,
      "--pq-signature",
      signatureHex,
      "--json",
    ]);

    expect(status).to.equal(0);
    expect(JSON.parse(stdout).result.verified).to.equal(true);
  });

  it("treats non-hex files as raw bytes", function () {
    const dir = mkdtempSync(join(tmpdir(), "pqverifier-"));
    const rawMessage = join(dir, "message.bin");
    const rawPublicKey = join(dir, "public-key.bin");
    const rawSignature = join(dir, "signature.bin");
    writeFileSync(rawMessage, Buffer.from(messageHex.slice(2), "hex"));
    writeFileSync(rawPublicKey, Buffer.from(publicKeyHex.slice(2), "hex"));
    writeFileSync(rawSignature, Buffer.from(signatureHex.slice(2), "hex"));

    const { status, stdout } = runCli([
      "--message-file",
      rawMessage,
      "--public-key-file",
      rawPublicKey,
      "--pq-signature-file",
      rawSignature,
      "--json",
    ]);

    expect(status).to.equal(0);
    expect(JSON.parse(stdout).result.verified).to.equal(true);
  });

  it("reports a failed verification as a successful process (exit 0, verified false)", function () {
    // Flip one byte of the signature.
    const tamperedSig = "0x" + (signatureHex[2] === "0" ? "1" : "0") + signatureHex.slice(3);
    const { status, stdout } = runCli([
      "--message",
      messageHex,
      "--public-key",
      publicKeyHex,
      "--pq-signature",
      tamperedSig,
      "--json",
    ]);

    expect(status).to.equal(0);
    expect(JSON.parse(stdout).result.verified).to.equal(false);
  });

  it("does not require ATTESTOR_PRIVATE_KEY", function () {
    const env = { ...process.env };
    delete env.ATTESTOR_PRIVATE_KEY;

    const { status, stdout } = runCli(
      [
        "--message-file",
        messageFile,
        "--public-key-file",
        publicKeyFile,
        "--pq-signature-file",
        signatureFile,
        "--json",
      ],
      env,
    );

    expect(status).to.equal(0);
    expect(JSON.parse(stdout).result.verified).to.equal(true);
  });

  it("never prints raw public key or signature material", function () {
    const { stdout } = runCli([
      "--message-file",
      messageFile,
      "--public-key-file",
      publicKeyFile,
      "--pq-signature-file",
      signatureFile,
      "--json",
    ]);

    expect(stdout).to.not.include(publicKeyHex.slice(2));
    expect(stdout).to.not.include(signatureHex.slice(2));
  });

  it("prints a concise human-readable result without --json", function () {
    const { status, stdout } = runCli([
      "--message-file",
      messageFile,
      "--public-key-file",
      publicKeyFile,
      "--pq-signature-file",
      signatureFile,
    ]);

    expect(status).to.equal(0);
    expect(stdout).to.include("verified:      true");
    expect(stdout).to.include("reason:        ML_DSA_65_VALID");
  });

  it("exits non-zero when an input has both inline and file forms", function () {
    const { status } = runCli([
      "--message",
      messageHex,
      "--message-file",
      messageFile,
      "--public-key-file",
      publicKeyFile,
      "--pq-signature-file",
      signatureFile,
      "--json",
    ]);

    expect(status).to.not.equal(0);
  });

  it("exits non-zero when a required input is missing", function () {
    const { status } = runCli(["--message-file", messageFile, "--json"]);
    expect(status).to.not.equal(0);
  });

  it("exits non-zero on an unknown command", function () {
    const result = spawnSync(process.execPath, [TS_NODE_BIN, "--esm", CLI, "bogus"], {
      encoding: "utf8",
      env: process.env,
    });
    expect(result.status).to.not.equal(0);
  });
});
