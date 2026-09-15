import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * NIST ACVP ML-DSA-65 differential conformance against the SP1 ACVP program (issue #29).
 *
 * GATED behind RUN_SP1_E2E=1 — these require the SP1 toolchain (`sp1up`) and a
 * built `mldsa65-host` binary, exactly like test/ZKRealProof.e2e.test.ts. CI runs
 * the mock verifier path only. See docs/ZK_Prover_Runbook.md and
 * docs/ACVP_Guest_Results.md.
 *
 * The guest crate builds two SP1 programs with separate ELFs and program vkeys: the
 * withdrawal program (`mldsa65-withdrawal`, the program a ZKMLDSAVerifier pins) and the
 * ACVP conformance program (`mldsa65-acvp`). This file feeds the OFFICIAL NIST ACVP
 * sigVer vectors (FIPS 204, external interface, pure) through the ACVP program with
 * `mldsa65-host acvp-execute`: every `testPassed: true` vector must verify and commit
 * keccak256 of its key, message, context and signature, and every `testPassed: false`
 * vector (and any tampered signature) must make it revert. It also checks the separation:
 * the two programs report different vkeys, and the withdrawal path accepts neither the
 * pre-remediation message/context routing nor an ACVP vector presented as a withdrawal.
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

/** The ACVP program's `inputs.json` for one vector. */
function acvpInputs(vec: AcvpVector, signatureHex = vec.signature) {
  return {
    publicKey: "0x" + vec.pk,
    message: "0x" + vec.message,
    context: "0x" + vec.context,
    signature: "0x" + signatureHex,
  };
}

/** The ACVP program's journal: keccak256 of the public key, message, context and signature. */
function acvpJournal(vec: AcvpVector): string {
  return ethers.concat([
    ethers.keccak256("0x" + vec.pk),
    ethers.keccak256("0x" + vec.message),
    ethers.keccak256("0x" + vec.context),
    ethers.keccak256("0x" + vec.signature),
  ]);
}

/** A vector's key and signature presented to the withdrawal path for digest keccak256(message). */
function vectorAsWithdrawal(vec: AcvpVector) {
  return {
    withdrawalDigest: ethers.keccak256("0x" + vec.message),
    publicKey: "0x" + vec.pk,
    signature: "0x" + vec.signature,
    chainId,
    verifierAddress,
  };
}

function runHost(command: string, inputs?: object): { status: number | null; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "mldsa65-acvp-"));
  const args = [command];
  try {
    if (inputs !== undefined) {
      const inputsPath = join(dir, "inputs.json");
      writeFileSync(inputsPath, JSON.stringify(inputs));
      args.push(inputsPath);
    }
    const result = spawnSync(hostBin, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (result.error) throw new Error(`failed to launch SP1 host (${hostBin}): ${result.error.message}`);
    return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

(runE2E ? describe : describe.skip)("NIST ACVP ML-DSA-65 through the SP1 ACVP program (RUN_SP1_E2E=1)", function () {
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
    it(`accepts valid ACVP vector tcId ${vec.tcId} (${ctxLabel}) and commits its hashes`, function () {
      const { status, stdout, stderr } = runHost("acvp-execute", acvpInputs(vec));
      expect(status, `ACVP program should accept valid vector tcId ${vec.tcId}; stderr: ${stderr}`).to.equal(0);
      const report = JSON.parse(stdout);
      expect(Number(report.cycles)).to.be.greaterThan(0);
      expect(String(report.publicValues).toLowerCase()).to.equal(acvpJournal(vec).toLowerCase());
    });
  }

  for (const vec of invalidVectors) {
    it(`rejects invalid ACVP vector tcId ${vec.tcId} (guest reverts)`, function () {
      const { status } = runHost("acvp-execute", acvpInputs(vec));
      expect(status, `ACVP program should reject invalid vector tcId ${vec.tcId}`).to.not.equal(0);
    });
  }

  it("rejects a tampered signature on an otherwise-valid ACVP vector (guest reverts)", function () {
    const vec = validVectors[0];
    // Flip the first signature byte; everything else stays a genuine NIST vector.
    const sigBytes = ethers.getBytes("0x" + vec.signature);
    sigBytes[0] ^= 0xff;
    const tamperedHex = ethers.hexlify(sigBytes).slice(2);

    const { status } = runHost("acvp-execute", acvpInputs(vec, tamperedHex));
    expect(status, `ACVP program should reject tampered signature for tcId ${vec.tcId}`).to.not.equal(0);
  });

  describe("program separation", function () {
    it("reports different program vkeys for the withdrawal and ACVP programs", function () {
      const withdrawal = runHost("vkey");
      const acvp = runHost("acvp-vkey");
      expect(withdrawal.status, withdrawal.stderr).to.equal(0);
      expect(acvp.status, acvp.stderr).to.equal(0);
      const withdrawalVkey = JSON.parse(withdrawal.stdout).vkey as string;
      const acvpVkey = JSON.parse(acvp.stdout).vkey as string;
      expect(withdrawalVkey).to.match(/^0x[0-9a-f]{64}$/);
      expect(acvpVkey).to.match(/^0x[0-9a-f]{64}$/);
      expect(withdrawalVkey).to.not.equal(acvpVkey);
    });

    it("withdrawal path refuses a genuine withdrawal input that also carries message/context keys", function () {
      const genuine = JSON.parse(readFileSync(resolve("zkvm/fixtures/mldsa65-withdrawal.inputs.json"), "utf8"));
      const accepted = runHost("execute", genuine);
      expect(accepted.status, `positive control: the committed withdrawal input; stderr: ${accepted.stderr}`).to.equal(
        0,
      );
      const withExtraKeys = runHost("execute", { ...genuine, message: "0x", context: "0x" });
      expect(withExtraKeys.status, "the withdrawal inputs.json has no message or context").to.not.equal(0);
    });

    for (const vec of validVectors) {
      it(`withdrawal path refuses the old message/context routing for tcId ${vec.tcId}`, function () {
        const oldRouting = { ...vectorAsWithdrawal(vec), message: "0x" + vec.message, context: "0x" + vec.context };
        const { status } = runHost("execute", oldRouting);
        expect(status, "the withdrawal inputs.json has no message or context").to.not.equal(0);
      });

      it(`withdrawal program rejects tcId ${vec.tcId}'s signature as a withdrawal authorization`, function () {
        const { status } = runHost("execute", vectorAsWithdrawal(vec));
        expect(status, "an ACVP signature is not a signature over the withdrawal digest").to.not.equal(0);
      });
    }
  });
});
