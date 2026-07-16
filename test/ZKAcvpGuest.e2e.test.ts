import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * NIST ACVP ML-DSA-65 differential conformance against the SP1 guest (issue #29).
 *
 * GATED behind RUN_SP1_E2E=1 — these require the SP1 toolchain (`sp1up`) and a
 * built `mldsa65-host` binary, exactly like test/ZKRealProof.e2e.test.ts. CI runs
 * the mock verifier path only. See docs/ZK_Prover_Runbook.md and
 * docs/ACVP_Guest_Results.md.
 *
 * Where ZKRealProof.e2e.test.ts proves the Rust guest agrees with the TypeScript
 * @noble/post-quantum implementation, this file feeds the OFFICIAL NIST ACVP
 * sigVer vectors (FIPS 204, external interface, pure) directly through the guest.
 * That checks the guest against the standard itself, not just against a sibling
 * implementation: every `testPassed: true` vector must verify inside the guest and
 * every `testPassed: false` vector (and any tampered signature) must make it revert.
 *
 * This is research-prototype conformance evidence, not an audit and not a complete
 * on-chain verifier. Passing these vectors does not make the vault production custody.
 */
const runE2E = process.env.RUN_SP1_E2E === "1";
const hostBin = process.env.SP1_HOST_BIN ?? join("zkvm", "host", "target", "release", "mldsa65-host");

interface AcvpVector {
  tcId: number;
  pk: string;
  message: string;
  context: string;
  signature: string;
  testPassed: boolean;
}

const fixturePath = resolve("test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  official: boolean;
  algorithm: string;
  signatureInterface: string;
  preHash: string;
  vectors: AcvpVector[];
};

const chainId = 31337;
const verifierAddress = "0x" + "11".repeat(20);

/** Build the guest `inputs.json` shape for one ACVP vector. */
function inputsForVector(vec: AcvpVector, signatureHex = vec.signature) {
  // The guest commits the withdrawal digest to its journal; for a conformance run
  // bind it deterministically to the signed message so the journal is meaningful.
  const messageBytes = ethers.getBytes("0x" + vec.message);
  return {
    withdrawalDigest: ethers.keccak256(messageBytes),
    publicKey: "0x" + vec.pk,
    signature: "0x" + signatureHex,
    chainId,
    verifierAddress,
    message: "0x" + vec.message,
    context: vec.context.length === 0 ? "0x" : "0x" + vec.context,
  };
}

function runHostExecute(inputs: object): { status: number | null; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "mldsa65-acvp-"));
  const inputsPath = join(dir, "inputs.json");
  try {
    writeFileSync(inputsPath, JSON.stringify(inputs));
    const result = spawnSync(hostBin, ["execute", inputsPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (result.error) throw new Error(`failed to launch SP1 host (${hostBin}): ${result.error.message}`);
    return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

(runE2E ? describe : describe.skip)("NIST ACVP ML-DSA-65 through SP1 guest (RUN_SP1_E2E=1)", function () {
  // Each vector is a full ML-DSA-65 verification in SP1 execute mode; the sweep
  // runs every fixture vector, so allow generous time.
  this.timeout(30 * 60 * 1000);

  before(function () {
    expect(fixture.official, "fixture must be official NIST vectors").to.equal(true);
    expect(fixture.algorithm).to.equal("ML-DSA-65");
    expect(fixture.signatureInterface).to.equal("external");
    expect(fixture.preHash).to.equal("pure");
  });

  const validVectors = fixture.vectors.filter((v) => v.testPassed);
  const invalidVectors = fixture.vectors.filter((v) => !v.testPassed);

  it("has both valid and invalid fixtures to exercise", function () {
    expect(validVectors.length, "need >=1 valid ACVP vector").to.be.greaterThan(0);
    expect(invalidVectors.length, "need >=1 invalid ACVP vector").to.be.greaterThan(0);
  });

  for (const vec of validVectors) {
    const ctxLabel = vec.context.length === 0 ? "empty ctx" : `${vec.context.length / 2}B ctx`;
    it(`accepts valid ACVP vector tcId ${vec.tcId} (${ctxLabel})`, function () {
      const { status, stdout, stderr } = runHostExecute(inputsForVector(vec));
      expect(status, `guest should accept valid vector tcId ${vec.tcId}; stderr: ${stderr}`).to.equal(0);
      const report = JSON.parse(stdout);
      expect(Number(report.cycles)).to.be.greaterThan(0);
      expect(report.publicValues).to.match(/^0x[0-9a-fA-F]+$/);
    });
  }

  for (const vec of invalidVectors) {
    it(`rejects invalid ACVP vector tcId ${vec.tcId} (guest reverts)`, function () {
      const { status } = runHostExecute(inputsForVector(vec));
      expect(status, `guest should reject invalid vector tcId ${vec.tcId}`).to.not.equal(0);
    });
  }

  it("rejects a tampered signature on an otherwise-valid ACVP vector (guest reverts)", function () {
    const vec = validVectors[0];
    // Flip the first signature byte; everything else stays a genuine NIST vector.
    const sigBytes = ethers.getBytes("0x" + vec.signature);
    sigBytes[0] ^= 0xff;
    const tamperedHex = ethers.hexlify(sigBytes).slice(2);

    const { status } = runHostExecute(inputsForVector(vec, tamperedHex));
    expect(status, `guest should reject tampered signature for tcId ${vec.tcId}`).to.not.equal(0);
  });
});
