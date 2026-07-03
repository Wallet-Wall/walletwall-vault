import { expect } from "chai";
import { MLDSASigner } from "../pqc/ml-dsa";

/**
 * NOTE ON NAMING: despite the "ZKVMDifferential" file name, this suite is NOT a
 * TS↔Rust differential test. It only exercises the TypeScript ML-DSA
 * implementation. A true differential test would compile and run the pinned Rust
 * SP1 guest against the SAME vectors and assert both implementations agree.
 * That coverage requires the Rust/SP1 toolchain and is intentionally NOT built
 * here (kept offline and toolchain-free). The gated placeholder at the bottom of
 * this file documents what real differential coverage would require.
 */
describe("ML-DSA TypeScript verifier (not a differential zkVM test)", function () {
  it("verifies TypeScript-generated material with the TypeScript implementation", async function () {
    const { publicKey, privateKey } = MLDSASigner.generateKeyPair();
    const digest = Buffer.alloc(32, 1); // 0x01...01
    const signature = MLDSASigner.sign(digest, privateKey);

    // Verify using the TS implementation only. This proves the TS signer and
    // verifier are self-consistent — it does NOT cross-check against the Rust guest.
    const isValidTS = MLDSASigner.verify(publicKey, digest, signature);
    expect(isValidTS).to.be.true;
  });
});

/**
 * PLACEHOLDER — real TS↔Rust differential coverage.
 *
 * This block is intentionally skipped. Enabling it requires compiling and
 * executing the pinned Rust SP1 guest (see zkvm/guest) and feeding it the SAME
 * ML-DSA vectors used above, then asserting the Rust guest and the TypeScript
 * implementation agree bit-for-bit on accept/reject for both valid and
 * tampered inputs. That work needs the Rust/SP1 toolchain and is out of scope
 * for this offline, toolchain-free test file — do NOT un-skip it without wiring
 * up a real guest build+execute harness (gate it behind an env flag such as
 * RUN_ZKVM_DIFFERENTIAL=1, mirroring the RUN_SP1_E2E gating used elsewhere).
 */
describe.skip("TS↔Rust ML-DSA differential (requires pinned Rust SP1 guest — not built here)", function () {
  it("TS and Rust guest agree on accept/reject for identical vectors", function () {
    // Intentionally unimplemented. Requires: build the pinned Rust SP1 guest,
    // execute it on shared valid + tampered vectors, and assert its accept/reject
    // decisions match MLDSASigner.verify() exactly.
    expect.fail("differential guest harness not wired up (see file header)");
  });
});
