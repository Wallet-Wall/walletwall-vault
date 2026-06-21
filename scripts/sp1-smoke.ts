/**
 * SP1 smoke lane — cheap, deterministic, execute-only.
 *
 * This is the reproducible "is the SP1/ZK lane wired correctly?" check. It is
 * intentionally split into two parts:
 *
 *   1. A pure, deterministic core that needs NO SP1 toolchain and runs in CI:
 *      it derives the guest journal (public values) for a committed ML-DSA-65
 *      fixture via ProverClient.encodePublicValues and asserts the encoding is
 *      well-formed and decodes back to the expected fields. This pins the
 *      TypeScript <-> Rust-guest journal contract without proving anything.
 *
 *   2. An OPTIONAL execute-only step: if a built `mldsa65-host` binary is present
 *      (SP1_HOST_BIN or the default release path), it runs the guest in SP1
 *      `execute` mode (no proving) on the same fixture and asserts the host's
 *      emitted public values match the expected journal. This needs the SP1
 *      toolchain but is far cheaper than proving.
 *
 * What this proves: the journal/public-value encoding is internally consistent
 * and (when the host is available) the Rust guest commits the same journal for a
 * known-good signature in execute mode.
 *
 * What this does NOT prove: nothing is proven (no Groth16 proof is generated),
 * there is no on-chain verification, no NIST conformance claim beyond the single
 * fixture, and no production readiness. Heavy proving / full differential e2e
 * stays gated behind RUN_SP1_E2E=1 (see test/ZKRealProof.e2e.test.ts,
 * test/ZKAcvpGuest.e2e.test.ts, docs/ZK_Prover_Runbook.md).
 *
 * Run: npm run sp1:smoke
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

import { ethers } from "ethers";

import { ProverClient } from "./prover-client";

/** Deterministic, local chain id + placeholder verifier used by the smoke fixture. */
export const SMOKE_CHAIN_ID = 31337n;
export const SMOKE_VERIFIER_ADDRESS = "0x" + "11".repeat(20);

const FIXTURE_DIR = resolve("test/fixtures/mldsa/library-generated");

export interface SmokeFixture {
  withdrawalDigest: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

function readHex(name: string): string {
  return readFileSync(join(FIXTURE_DIR, name), "utf8").trim();
}

/** Load the committed, valid ML-DSA-65 fixture triple. */
export function loadSmokeFixture(): SmokeFixture {
  return {
    withdrawalDigest: readHex("message.hex"),
    publicKey: ethers.getBytes(readHex("public-key.hex")),
    signature: ethers.getBytes(readHex("signature.hex")),
  };
}

/** Build the guest `inputs.json` shape for the fixture (withdrawal path). */
export function buildSmokeInputs(fixture: SmokeFixture = loadSmokeFixture()) {
  return {
    withdrawalDigest: fixture.withdrawalDigest,
    publicKey: ethers.hexlify(fixture.publicKey),
    signature: ethers.hexlify(fixture.signature),
    chainId: Number(SMOKE_CHAIN_ID),
    verifierAddress: SMOKE_VERIFIER_ADDRESS,
  };
}

/** Pure, deterministic expected guest journal for the fixture. */
export function computeExpectedPublicValues(fixture: SmokeFixture = loadSmokeFixture()): string {
  return ProverClient.encodePublicValues(
    fixture.withdrawalDigest,
    fixture.publicKey,
    fixture.signature,
    SMOKE_CHAIN_ID,
    SMOKE_VERIFIER_ADDRESS,
  );
}

/** Resolve a built host binary if one is available; otherwise null (skip execute). */
export function resolveHostBinOrNull(): string | null {
  const configured = process.env.SP1_HOST_BIN ?? join("zkvm", "host", "target", "release", "mldsa65-host");
  const absolute = isAbsolute(configured) ? configured : resolve(configured);
  return existsSync(absolute) && statSync(absolute).isFile() ? absolute : null;
}

export interface HostExecuteResult {
  cycles: number;
  publicValues: string;
}

/** Run the guest in SP1 execute mode (no proving). Throws on host failure. */
export function runHostExecute(hostBin: string, inputs: object): HostExecuteResult {
  const dir = mkdtempSync(join(tmpdir(), "sp1-smoke-"));
  const inputsPath = join(dir, "inputs.json");
  try {
    writeFileSync(inputsPath, JSON.stringify(inputs));
    const result = spawnSync(hostBin, ["execute", inputsPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (result.error) throw new Error(`failed to launch SP1 host (${hostBin}): ${result.error.message}`);
    if (result.status !== 0) {
      throw new Error(`SP1 host execute exited with ${result.status}: ${result.stderr?.trim() ?? ""}`);
    }
    const out = JSON.parse(result.stdout) as { cycles: number; publicValues: string };
    return { cycles: out.cycles, publicValues: out.publicValues };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface SmokeSummary {
  mode: "sp1-smoke";
  proven: false;
  fixture: { messageHash: string; publicKeyHash: string; signatureHash: string };
  expectedPublicValues: string;
  expectedPublicValuesHash: string;
  hostExecuted: boolean;
  cycles: number | null;
  hostMatchesExpected: boolean | null;
}

/**
 * Run the smoke lane. The pure core always runs; the execute step runs only if a
 * built host binary is available. Throws if any check fails.
 */
export function runSmoke(): SmokeSummary {
  const fixture = loadSmokeFixture();
  const expected = computeExpectedPublicValues(fixture);

  // The journal is exactly 5 * 32-byte words; assert shape and decodability.
  if (!ethers.isHexString(expected) || ethers.dataLength(expected) !== 160) {
    throw new Error(`expected public values must be 160 bytes, got ${ethers.dataLength(expected)}`);
  }
  const decoded = new ethers.AbiCoder().decode(["bytes32", "bytes32", "bytes32", "uint64", "address"], expected);
  if (decoded[0].toLowerCase() !== fixture.withdrawalDigest.toLowerCase()) {
    throw new Error("decoded withdrawalDigest does not match fixture");
  }
  if (decoded[1].toLowerCase() !== ethers.keccak256(fixture.publicKey).toLowerCase()) {
    throw new Error("decoded publicKeyHash does not match fixture");
  }
  if (decoded[2].toLowerCase() !== ethers.keccak256(fixture.signature).toLowerCase()) {
    throw new Error("decoded signatureHash does not match fixture");
  }

  const summary: SmokeSummary = {
    mode: "sp1-smoke",
    proven: false,
    fixture: {
      messageHash: ethers.keccak256(fixture.withdrawalDigest),
      publicKeyHash: ethers.keccak256(fixture.publicKey),
      signatureHash: ethers.keccak256(fixture.signature),
    },
    expectedPublicValues: expected,
    expectedPublicValuesHash: ethers.keccak256(expected),
    hostExecuted: false,
    cycles: null,
    hostMatchesExpected: null,
  };

  const hostBin = resolveHostBinOrNull();
  if (hostBin) {
    const exec = runHostExecute(hostBin, buildSmokeInputs(fixture));
    summary.hostExecuted = true;
    summary.cycles = exec.cycles;
    summary.hostMatchesExpected = exec.publicValues.toLowerCase() === expected.toLowerCase();
    if (!summary.hostMatchesExpected) {
      throw new Error(`host execute public values ${exec.publicValues} do not match expected ${expected}`);
    }
  }

  return summary;
}

function main(): void {
  const summary = runSmoke();
  console.log(JSON.stringify(summary, null, 2));
  if (!summary.hostExecuted) {
    console.log(
      "\nSP1 host binary not found — ran the pure deterministic journal check only.\n" +
        "Build zkvm/host and re-run (or set SP1_HOST_BIN) for an execute-only differential.\n" +
        "Heavy proving / full e2e stays gated behind RUN_SP1_E2E=1. See docs/ZK_Prover_Runbook.md.",
    );
  }
}

if (process.argv[1]?.includes("sp1-smoke")) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
