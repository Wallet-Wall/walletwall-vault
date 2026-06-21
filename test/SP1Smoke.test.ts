/**
 * Tests for the SP1 smoke lane (scripts/sp1-smoke.ts) and the public-value
 * derivation it shares with the proof path (scripts/prover-client.ts).
 *
 * These run in CI with NO SP1 toolchain: they exercise the pure, deterministic
 * journal-encoding core only. The optional execute-only host step and all heavy
 * proving stay out of CI (host-binary-gated and RUN_SP1_E2E=1 respectively).
 */
import { ethers } from "ethers";
import { expect } from "chai";

import { ProverClient } from "../scripts/prover-client";
import {
  SMOKE_CHAIN_ID,
  SMOKE_VERIFIER_ADDRESS,
  buildSmokeInputs,
  computeExpectedPublicValues,
  loadSmokeFixture,
  runSmoke,
} from "../scripts/sp1-smoke";

describe("SP1 smoke lane (execute-only, fixture-only)", function () {
  it("runs the pure deterministic core without a host binary in CI", function () {
    const summary = runSmoke();
    expect(summary.mode).to.equal("sp1-smoke");
    expect(summary.proven).to.equal(false);
    // CI has no built host binary, so the execute step is skipped (not failed).
    expect(summary.hostExecuted).to.equal(false);
    expect(summary.cycles).to.equal(null);
    expect(summary.hostMatchesExpected).to.equal(null);
  });

  it("produces a deterministic 160-byte journal that decodes to the fixture", function () {
    const fixture = loadSmokeFixture();
    const a = computeExpectedPublicValues(fixture);
    const b = computeExpectedPublicValues(fixture);
    expect(a).to.equal(b);
    expect(ethers.dataLength(a)).to.equal(160); // 5 * 32-byte words

    const [digest, pkHash, sigHash, chainId, verifier] = new ethers.AbiCoder().decode(
      ["bytes32", "bytes32", "bytes32", "uint64", "address"],
      a,
    );
    expect(digest.toLowerCase()).to.equal(fixture.withdrawalDigest.toLowerCase());
    expect(pkHash).to.equal(ethers.keccak256(fixture.publicKey));
    expect(sigHash).to.equal(ethers.keccak256(fixture.signature));
    expect(chainId).to.equal(SMOKE_CHAIN_ID);
    expect(ethers.getAddress(verifier)).to.equal(ethers.getAddress(SMOKE_VERIFIER_ADDRESS));
  });

  it("smoke journal matches the journal embedded in a full proof payload", function () {
    const fixture = loadSmokeFixture();
    const expected = computeExpectedPublicValues(fixture);
    // encodeProof wraps the SAME journal with proof bytes; the smoke check and the
    // proof path must agree on the public values bit-for-bit.
    const payload = ProverClient.encodeProof(
      fixture.withdrawalDigest,
      fixture.publicKey,
      fixture.signature,
      SMOKE_CHAIN_ID,
      SMOKE_VERIFIER_ADDRESS,
      "0x" + "ab".repeat(32),
    );
    const [publicValues] = new ethers.AbiCoder().decode(["bytes", "bytes"], payload);
    expect(publicValues).to.equal(expected);
  });

  it("builds a guest inputs.json shape with hex fields and the local chain id", function () {
    const inputs = buildSmokeInputs();
    expect(inputs.withdrawalDigest).to.match(/^0x[0-9a-fA-F]{64}$/);
    expect(ethers.dataLength(inputs.publicKey)).to.equal(1952);
    expect(ethers.dataLength(inputs.signature)).to.equal(3309);
    expect(inputs.chainId).to.equal(Number(SMOKE_CHAIN_ID));
    expect(inputs.verifierAddress).to.equal(SMOKE_VERIFIER_ADDRESS);
  });

  it("rejects malformed inputs in the shared public-value derivation", function () {
    const fixture = loadSmokeFixture();
    expect(() =>
      ProverClient.encodePublicValues(
        fixture.withdrawalDigest,
        new Uint8Array(10), // wrong public-key length
        fixture.signature,
        SMOKE_CHAIN_ID,
        SMOKE_VERIFIER_ADDRESS,
      ),
    ).to.throw(/1952 bytes/);
    expect(() =>
      ProverClient.encodePublicValues(
        "0x1234", // not a bytes32 digest
        fixture.publicKey,
        fixture.signature,
        SMOKE_CHAIN_ID,
        SMOKE_VERIFIER_ADDRESS,
      ),
    ).to.throw(/bytes32/);
  });
});
