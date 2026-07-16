import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { MLDSASigner } from "../pqc/ml-dsa";

/**
 * End-to-end SP1 guest checks. These are GATED behind RUN_SP1_E2E=1 because they
 * require the SP1 toolchain (`sp1up`) and a built `mldsa65-host` binary; CI runs
 * the mock verifier path only. See docs/ZK_Prover_Runbook.md.
 *
 * The positive case is also the TS<->Rust differential test that
 * docs/ZK_Verifier_Feasibility.md calls for: a signature produced by the
 * TypeScript @noble/post-quantum implementation must verify inside the Rust
 * `ml-dsa` guest for the same digest, or the guest execution reverts.
 */
const runE2E = process.env.RUN_SP1_E2E === "1";

function resolveHostBin(): string {
  const configured = process.env.SP1_HOST_BIN ?? join("zkvm", "host", "target", "release", "mldsa65-host");
  const absolute = isAbsolute(configured) ? configured : resolve(configured);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) {
    throw new Error(`SP1 host binary not found at ${absolute}; build zkvm/host or set SP1_HOST_BIN to its path`);
  }
  return absolute;
}

function runHostExecute(inputs: object): { status: number | null; stdout: string; stderr: string } {
  const hostBin = resolveHostBin();
  const dir = mkdtempSync(join(tmpdir(), "mldsa65-e2e-"));
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

(runE2E ? describe : describe.skip)("ZK guest execute (SP1, RUN_SP1_E2E=1)", function () {
  // Proving/execution is slow; give it room.
  this.timeout(10 * 60 * 1000);

  const chainId = 31337;
  const verifierAddress = "0x" + "11".repeat(20);

  it("accepts a TS-generated ML-DSA-65 signature in the Rust guest and reports a cycle count", function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    const digest = ethers.keccak256(ethers.toUtf8Bytes("walletwall-e2e-digest"));
    const signature = MLDSASigner.sign(digest, privateKey);

    // Cross-check the TS verifier agrees before paying for guest execution.
    expect(MLDSASigner.verify(publicKey, digest, signature)).to.equal(true);

    const { status, stdout, stderr } = runHostExecute({
      withdrawalDigest: digest,
      publicKey: ethers.hexlify(publicKey),
      signature: ethers.hexlify(signature),
      chainId,
      verifierAddress,
    });

    expect(status, `host stderr: ${stderr}`).to.equal(0);
    const report = JSON.parse(stdout);
    expect(Number(report.cycles)).to.be.greaterThan(0);
    expect(report.publicValues).to.match(/^0x[0-9a-fA-F]+$/);
  });

  it("rejects a tampered signature (guest reverts)", function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    const digest = ethers.keccak256(ethers.toUtf8Bytes("walletwall-e2e-digest"));
    const signature = MLDSASigner.sign(digest, privateKey);
    signature[0] ^= 0xff;

    const { status } = runHostExecute({
      withdrawalDigest: digest,
      publicKey: ethers.hexlify(publicKey),
      signature: ethers.hexlify(signature),
      chainId,
      verifierAddress,
    });

    expect(status).to.not.equal(0);
  });
});
