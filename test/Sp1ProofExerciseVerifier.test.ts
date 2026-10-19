/**
 * SP1-PA3A: the designated verifier path, exercised on a development chain.
 *
 * A pure validator cannot execute a pairing, so the proof-exercise evidence records the designated verifier's answer
 * in a verification observation and this suite is the layer that RE-EXECUTES it: the CREATE2-authenticated v6.1.0
 * runtime (SP1-TD1's initcode, whose keccak the designation pins) is deployed on the development chain, its code hash
 * must be the designation's, and `verifyProof` is asked. The positive control is SP1-TD1's real mainnet proof (it
 * verifies, and its tampered copy reverts ProofInvalid); the negative controls are a synthetic proof and the real
 * proof with one byte flipped. Whenever a proof-exercise record is committed, its proof must verify here, on every
 * run: a verification observation forged without a proof the runtime accepts fails this suite.
 *
 * Nothing here proves. The real checkout holds no proof-exercise evidence. Research prototype. Not audited.
 */
import { expect } from "chai";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { getBytes, hexlify, keccak256 } from "ethers";

import { PROOF_INVALID, REAL_PROOF_REL } from "../scripts/lib/sp1-chain-execution";
import { latestDesignation, readDesignations, type ProgramDesignation } from "../scripts/lib/sp1-designation";
import {
  LOCAL_RUNTIME,
  VERIFICATION_SCHEMA,
  authenticatedInitcode,
  deployRuntime,
  exerciseObservationsIn,
  exerciseRecordsIn,
  verificationObservationFor,
  verifyWithRuntime,
  type RunObservation,
} from "../scripts/lib/sp1-proof-exercise";
import { ethers } from "./helpers/connection";
import { RUN_REL, runObservation, runSha, verificationObservation } from "./helpers/sp1ProofExercise";

describe("SP1-PA3A — the designated verifier path (a development chain)", function () {
  const d1 = latestDesignation(readDesignations(".")) as ProgramDesignation;
  const realProof = () =>
    JSON.parse(readFileSync(REAL_PROOF_REL, "utf8")).call as {
      programVKey: string;
      publicValues: string;
      proofBytes: string;
    };
  let address: string;

  before(async function () {
    this.timeout(120_000);
    const [deployer] = await ethers.getSigners();
    address = await deployRuntime(deployer, authenticatedInitcode(".", d1));
  });

  it("deploys the CREATE2-authenticated initcode and gets the designated runtime; another initcode is refused", async function () {
    const initcode = authenticatedInitcode(".", d1);
    expect(keccak256(initcode)).to.equal(d1.verifier.create2.initcodeKeccak);
    expect(keccak256(await ethers.provider.getCode(address))).to.equal(d1.verifier.runtimeCodeKeccak);
    const other = structuredClone(d1);
    other.verifier.create2.initcodeKeccak = `0x${"00".repeat(32)}`;
    assert.throws(() => authenticatedInitcode(".", other), /not the CREATE2-authenticated initcode/);
    const unauthenticated = structuredClone(d1);
    unauthenticated.verifier.create2.authenticated = false;
    assert.throws(() => authenticatedInitcode(".", unauthenticated), /not the CREATE2-authenticated initcode/);
  });

  it("accepts SP1-TD1's real v6.1.0 proof and refuses its tampered copy (the positive control)", async function () {
    this.timeout(120_000);
    const proof = realProof();
    const check = await verifyWithRuntime(ethers.provider, { address, ...proof, mode: LOCAL_RUNTIME });
    expect(check).to.deep.include({
      address,
      runtimeCodeKeccak: d1.verifier.runtimeCodeKeccak,
      mode: LOCAL_RUNTIME,
      verdicts: { real: "success", tampered: `revert ${PROOF_INVALID}` },
    });
    expect(check.chainId).to.match(/^[0-9]+$/);
    expect(check.block).to.be.a("number").and.greaterThan(0);
  });

  it("refuses what the runtime does not accept: the real proof with one byte flipped, and a synthetic proof", async function () {
    this.timeout(120_000);
    const proof = realProof();
    const flipped = getBytes(proof.proofBytes);
    flipped[flipped.length - 1] ^= 1;
    const bad = await verifyWithRuntime(ethers.provider, {
      address,
      programVKey: proof.programVKey,
      publicValues: proof.publicValues,
      proofBytes: hexlify(flipped),
      mode: LOCAL_RUNTIME,
    });
    expect(bad.verdicts.real).to.equal(`revert ${PROOF_INVALID}`);
    const synthetic = runObservation().proof;
    const s = await verifyWithRuntime(ethers.provider, {
      address,
      programVKey: synthetic.vkey,
      publicValues: synthetic.publicValues,
      proofBytes: synthetic.proofBytes,
      mode: LOCAL_RUNTIME,
    });
    expect(s.verdicts.real).to.match(/^revert /);
    expect(s.verdicts.real).to.not.equal("success");
  });

  it("the verification observation is ACCEPTED only when every check accepted the proof and refused the tampered copy", function () {
    const run = runObservation();
    const bound = { path: RUN_REL, sha256: runSha(run), observation: run };
    const check = verificationObservation(run).checks[0];
    const input = {
      host: "proving-host-a",
      scriptSha256: "22".repeat(32),
      run: bound,
      verifier: run.anchor.verifier,
      checks: [check],
      clock: () => "2026-11-01T12:30:00Z",
    };
    const ok = verificationObservationFor(input);
    expect(ok).to.deep.include({
      schema: VERIFICATION_SCHEMA,
      host: "proving-host-a",
      measuredAtUtc: "2026-11-01T12:30:00Z",
      run: { path: RUN_REL, sha256: runSha(run) },
      proof: {
        vkey: run.proof.vkey,
        publicValuesSha256: run.proof.publicValuesSha256,
        proofBytesSha256: run.proof.proofBytesSha256,
      },
      verifier: run.anchor.verifier,
      acceptance: "ACCEPTED",
    });
    expect(ok.checks).to.deep.equal([check]);
    const rejected = verificationObservationFor({
      ...input,
      checks: [{ ...check, verdicts: { real: `revert ${PROOF_INVALID}`, tampered: `revert ${PROOF_INVALID}` } }],
    });
    expect(rejected.acceptance).to.equal("REJECTED");
    // A runtime that accepts the tampered copy is not the designated verifier's behavior: rejected too.
    expect(
      verificationObservationFor({
        ...input,
        checks: [{ ...check, verdicts: { real: "success", tampered: "success" } }],
      }).acceptance,
    ).to.equal("REJECTED");
    expect(verificationObservationFor({ ...input, checks: [] }).acceptance).to.equal("REJECTED");
    // Every check must accept: one deployed check rejecting beside an accepting local one rejects the whole.
    expect(
      verificationObservationFor({
        ...input,
        checks: [
          check,
          {
            ...check,
            chainId: "11155111",
            mode: "DEPLOYED",
            verdicts: { real: `revert 0x`, tampered: `revert ${PROOF_INVALID}` },
          },
        ],
      }).acceptance,
    ).to.equal("REJECTED");
  });

  it("the real checkout holds no proof-exercise evidence; a committed exercise's proof is re-executed here on every run", async function () {
    this.timeout(300_000);
    const observations = exerciseObservationsIn(".");
    if (exerciseRecordsIn(".").length === 0) {
      expect(observations).to.deep.equal({ run: [], verification: [], other: [] });
      return;
    }
    // Once SP1-PA3B commits an exercise: its proof must verify against the authenticated runtime, and name d1's key.
    const run = JSON.parse(readFileSync(observations.run[0], "utf8")) as RunObservation;
    expect(run.proof.vkey).to.equal(d1.programVKey);
    const check = await verifyWithRuntime(ethers.provider, {
      address,
      programVKey: run.proof.vkey,
      publicValues: run.proof.publicValues,
      proofBytes: run.proof.proofBytes,
      mode: LOCAL_RUNTIME,
    });
    expect(check.verdicts).to.deep.equal({ real: "success", tampered: `revert ${PROOF_INVALID}` });
    expect(check.runtimeCodeKeccak).to.equal(d1.verifier.runtimeCodeKeccak);
  });
});
