/**
 * SP1-PA3D, Phase 6: the verifier-class negative controls, executed on a development chain against the designated
 * verifier (the CREATE2-authenticated v6.1.0 runtime, as SP1-PA3A's suite deploys it). The committed PA3D proof is the
 * positive control (accepted, its tampered copy refused); then the same proof with one byte flipped, under a wrong
 * program verifying key, over wrong public values, truncated by a byte, and with another selector, each asked of the
 * same runtime and each refused. The validator-class controls (mutated evidence refused by the record's chain) run in
 * test/Sp1Pa3dRecord.test.ts. Nothing here proves. Skipped while no PA3D record is committed. Research prototype. Not
 * audited.
 */
import { expect } from "chai";
import { existsSync, readFileSync } from "node:fs";

import { getBytes, hexlify } from "ethers";

import { PROOF_INVALID } from "../scripts/lib/sp1-chain-execution";
import { latestDesignation, readDesignations, type ProgramDesignation } from "../scripts/lib/sp1-designation";
import { PA3D_NEGATIVE_CONTROLS, RECORD_REL, type Pa3dRecord } from "../scripts/lib/sp1-pa3d-record";
import {
  LOCAL_RUNTIME,
  authenticatedInitcode,
  deployRuntime,
  verifyWithRuntime,
  type RunObservation,
} from "../scripts/lib/sp1-proof-exercise";
import { ethers } from "./helpers/connection";

const lf = (text: string) => text.replace(/\r\n/g, "\n");

describe("SP1-PA3D — the verifier-class negative controls (a development chain)", function () {
  this.timeout(180_000);
  const d1 = latestDesignation(readDesignations(".")) as ProgramDesignation;
  let address: string;
  let proof: { programVKey: string; publicValues: string; proofBytes: string };
  const flipLast = (hex: string) => {
    const b = getBytes(hex);
    b[b.length - 1] ^= 1;
    return hexlify(b);
  };

  before(async function () {
    if (!existsSync(RECORD_REL)) this.skip();
    const record = JSON.parse(lf(readFileSync(RECORD_REL, "utf8"))) as Pa3dRecord;
    if (record.exercise === null) this.skip();
    const run = JSON.parse(lf(readFileSync(record.exercise.run.path, "utf8"))) as RunObservation;
    proof = { programVKey: run.proof.vkey, publicValues: run.proof.publicValues, proofBytes: run.proof.proofBytes };
    const [deployer] = await ethers.getSigners();
    address = await deployRuntime(deployer, authenticatedInitcode(".", d1));
  });

  it("the positive control: the designated runtime accepts the committed PA3D proof and refuses its tampered copy", async function () {
    const check = await verifyWithRuntime(ethers.provider, { address, ...proof, mode: LOCAL_RUNTIME });
    expect(check.runtimeCodeKeccak).to.equal(d1.verifier.runtimeCodeKeccak);
    expect(check.verdicts).to.deep.equal({ real: "success", tampered: `revert ${PROOF_INVALID}` });
  });

  it("NC-V1: one byte of the proof flipped is refused as ProofInvalid", async function () {
    const c = await verifyWithRuntime(ethers.provider, {
      address,
      ...proof,
      proofBytes: flipLast(proof.proofBytes),
      mode: LOCAL_RUNTIME,
    });
    expect(c.verdicts.real).to.equal(`revert ${PROOF_INVALID}`);
  });

  it("NC-V2: a wrong program verifying key is refused as ProofInvalid", async function () {
    const c = await verifyWithRuntime(ethers.provider, {
      address,
      ...proof,
      programVKey: flipLast(proof.programVKey),
      mode: LOCAL_RUNTIME,
    });
    expect(c.verdicts.real).to.equal(`revert ${PROOF_INVALID}`);
  });

  it("NC-V3: wrong public values are refused as ProofInvalid", async function () {
    const c = await verifyWithRuntime(ethers.provider, {
      address,
      ...proof,
      publicValues: flipLast(proof.publicValues),
      mode: LOCAL_RUNTIME,
    });
    expect(c.verdicts.real).to.equal(`revert ${PROOF_INVALID}`);
  });

  it("NC-V4: the proof truncated by its last byte is refused (a revert, never success)", async function () {
    const c = await verifyWithRuntime(ethers.provider, {
      address,
      ...proof,
      proofBytes: proof.proofBytes.slice(0, -2),
      mode: LOCAL_RUNTIME,
    });
    expect(c.verdicts.real).to.match(/^revert /);
  });

  it("NC-V5: another four-byte selector is refused (a revert, never success)", async function () {
    const b = getBytes(proof.proofBytes);
    b[0] ^= 0xff;
    const c = await verifyWithRuntime(ethers.provider, {
      address,
      ...proof,
      proofBytes: hexlify(b),
      mode: LOCAL_RUNTIME,
    });
    expect(c.verdicts.real).to.match(/^revert /);
    expect(c.verdicts.real).to.not.equal(`revert ${PROOF_INVALID}`);
  });

  it("the record declares exactly these verifier-class controls", function () {
    const declared = PA3D_NEGATIVE_CONTROLS.filter((c) => c.kind === "VERIFIER").map((c) => c.id);
    expect(declared).to.deep.equal(["NC-V1", "NC-V2", "NC-V3", "NC-V4", "NC-V5"]);
    const record = JSON.parse(lf(readFileSync(RECORD_REL, "utf8"))) as Pa3dRecord;
    expect(record.negativeControls.filter((c) => c.kind === "VERIFIER").map((c) => c.id)).to.deep.equal(declared);
  });
});
