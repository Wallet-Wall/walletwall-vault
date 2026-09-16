import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { ProverClient } from "../scripts/prover-client";

/**
 * ZKMLDSAVerifier accepts a proof only for the program it pins, and only for the public binding
 * fields of the call it is verifying.
 *
 * `ProgramBoundMockSP1Verifier` (test-only) verifies a proof only for a (program vkey, public values)
 * pair registered as proven, which is SP1 soundness at the program boundary. So a proof of the ACVP
 * conformance program, or of any program other than PROGRAM_VKEY, must not satisfy the verifier even
 * when its public values are byte for byte a valid withdrawal journal. The vkeys here are labelled test
 * identities, not the programs' measured vkeys (those come from `mldsa65-host vkey` / `acvp-vkey`).
 */
describe("ZKMLDSAVerifier program identity and public bindings", function () {
  const WITHDRAWAL_PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("test identity: mldsa65-withdrawal program"));
  const ACVP_PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("test identity: mldsa65-acvp program"));
  const PROOF_BYTES = "0x01";

  const digest = ethers.keccak256(ethers.toUtf8Bytes("program identity: a withdrawal digest"));
  const otherDigest = ethers.keccak256(ethers.toUtf8Bytes("program identity: another withdrawal digest"));
  const publicKey = new Uint8Array(1952).fill(0x07);
  const otherPublicKey = new Uint8Array(1952).fill(0x08);
  const signature = new Uint8Array(3309).fill(0x09);

  let sp1: any;
  let chainId: bigint;

  beforeEach(async function () {
    sp1 = await (await ethers.getContractFactory("ProgramBoundMockSP1Verifier")).deploy();
    chainId = (await ethers.provider.getNetwork()).chainId;
  });

  async function deployVerifier(programVKey: string) {
    return (await ethers.getContractFactory("ZKMLDSAVerifier")).deploy(await sp1.getAddress(), programVKey);
  }

  function journal(overrides: { digest?: string; publicKey?: Uint8Array; chainId?: bigint; verifier: string }) {
    return ProverClient.encodePublicValues(
      overrides.digest ?? digest,
      overrides.publicKey ?? publicKey,
      signature,
      overrides.chainId ?? chainId,
      overrides.verifier,
    );
  }

  function payload(publicValues: string, proofBytes = PROOF_BYTES) {
    return ethers.AbiCoder.defaultAbiCoder().encode(["bytes", "bytes"], [publicValues, proofBytes]);
  }

  describe("program identity", function () {
    it("positive control: accepts a withdrawal journal proven for its own PROGRAM_VKEY", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      expect(await verifier.PROGRAM_VKEY()).to.equal(WITHDRAWAL_PROGRAM_VKEY);
      const publicValues = journal({ verifier: await verifier.getAddress() });
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, publicValues);
      expect(await verifier.verify(digest, publicKey, payload(publicValues))).to.equal(true);
    });

    it("rejects the same withdrawal journal when only an ACVP-program proof of it exists", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const publicValues = journal({ verifier: await verifier.getAddress() });
      await sp1.setProven(ACVP_PROGRAM_VKEY, publicValues);
      expect(await verifier.verify(digest, publicKey, payload(publicValues))).to.equal(false);
    });

    it("rejects an ACVP-program proof even when the proof bytes name the ACVP program", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const publicValues = journal({ verifier: await verifier.getAddress() });
      await sp1.setProven(ACVP_PROGRAM_VKEY, publicValues);
      expect(await verifier.verify(digest, publicKey, payload(publicValues, ACVP_PROGRAM_VKEY))).to.equal(false);
    });

    it("reverse: a verifier pinned to the ACVP program does not accept a withdrawal-program proof", async function () {
      const acvpPinned = await deployVerifier(ACVP_PROGRAM_VKEY);
      const publicValues = journal({ verifier: await acvpPinned.getAddress() });
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, publicValues);
      expect(await acvpPinned.verify(digest, publicKey, payload(publicValues))).to.equal(false);
    });
  });

  describe("public binding fields (each journal is proven, so only ZKMLDSAVerifier's own check can refuse)", function () {
    it("refuses a journal committing another withdrawal digest", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const publicValues = journal({ digest: otherDigest, verifier: await verifier.getAddress() });
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, publicValues);
      expect(await verifier.verify(otherDigest, publicKey, payload(publicValues)), "positive control").to.equal(true);
      expect(await verifier.verify(digest, publicKey, payload(publicValues))).to.equal(false);
    });

    it("refuses a journal committing another public-key hash", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const publicValues = journal({ publicKey: otherPublicKey, verifier: await verifier.getAddress() });
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, publicValues);
      expect(await verifier.verify(digest, otherPublicKey, payload(publicValues)), "positive control").to.equal(true);
      expect(await verifier.verify(digest, publicKey, payload(publicValues))).to.equal(false);
    });

    it("refuses a journal committing another chain id", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const verifierAddress = await verifier.getAddress();
      const own = journal({ verifier: verifierAddress });
      const foreign = journal({ chainId: chainId + 1n, verifier: verifierAddress });
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, own);
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, foreign);
      expect(await verifier.verify(digest, publicKey, payload(own)), "positive control").to.equal(true);
      expect(await verifier.verify(digest, publicKey, payload(foreign))).to.equal(false);
    });

    it("refuses a journal committing another verifier address", async function () {
      const verifier = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const other = await deployVerifier(WITHDRAWAL_PROGRAM_VKEY);
      const own = journal({ verifier: await verifier.getAddress() });
      const foreign = journal({ verifier: await other.getAddress() });
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, own);
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, foreign);
      expect(await verifier.verify(digest, publicKey, payload(own)), "positive control").to.equal(true);
      expect(await verifier.verify(digest, publicKey, payload(foreign))).to.equal(false);
    });
  });
});
