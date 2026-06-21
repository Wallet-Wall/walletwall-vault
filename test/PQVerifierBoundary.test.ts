/**
 * Static boundary guards for the open PQ verifier module (src/verifier).
 *
 * These tests read the verifier source files and assert structural invariants
 * that keep the boundary clean, independently of runtime behavior:
 *
 *   - the verifier never signs anything (no ML-DSA keygen/sign, no EIP-712 / EVM
 *     signing),
 *   - the verifier never reads an attestor key or any environment variable,
 *   - the verifier never depends on the Hardhat runtime,
 *   - the verifier never imports the trusted attestation layer (the dependency
 *     direction is one-way: attestation consumes the verifier, never the reverse),
 *   - the schema module stays a dependency-free leaf (no imports at all).
 *
 * Comments are stripped before scanning so that the boundary's own prose (which
 * deliberately mentions "attestation", "EIP-712", "ATTESTOR_PRIVATE_KEY", and
 * "Hardhat" to document what it must NOT do) cannot trip these guards. Only real
 * code — imports and calls — is checked.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

const VERIFIER_FILES = [
  "src/verifier/schema.ts",
  "src/verifier/result.ts",
  "src/verifier/ml-dsa-65.ts",
  "src/verifier/evidence.ts",
];

/** Remove block and line comments so only executable code is scanned. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
}

function readCode(path: string): string {
  return stripComments(readFileSync(resolve(path), "utf8"));
}

describe("Open PQ verifier boundary (static source guards)", function () {
  const sources = new Map(VERIFIER_FILES.map((f) => [f, readCode(f)]));

  it("never signs, generates keys, or constructs EVM/EIP-712 signatures", function () {
    for (const [file, code] of sources) {
      expect(code, `${file} must not call ML-DSA keygen`).to.not.match(/\bkeygen\s*\(/);
      // Match `.sign(` (ML-DSA signing) but not `.signatureHash` / identifiers.
      expect(code, `${file} must not sign`).to.not.match(/\.sign\s*\(/);
      expect(code, `${file} must not sign EVM messages`).to.not.match(/signMessage|signTypedData|_signTypedData/);
    }
  });

  it("never reads ATTESTOR_PRIVATE_KEY or any environment variable", function () {
    for (const [file, code] of sources) {
      expect(code, `${file} must not read process.env`).to.not.match(/process\.env/);
      expect(code, `${file} must not reference ATTESTOR_PRIVATE_KEY in code`).to.not.match(/ATTESTOR_PRIVATE_KEY/);
    }
  });

  it("never imports the Hardhat runtime", function () {
    for (const [file, code] of sources) {
      expect(code, `${file} must not import hardhat`).to.not.match(/from\s+['"]hardhat['"]/);
      expect(code, `${file} must not require hardhat`).to.not.match(/require\(\s*['"]hardhat/);
    }
  });

  it("never imports the trusted attestation layer (one-way dependency)", function () {
    for (const [file, code] of sources) {
      // The verifier must not import scripts/* or anything named "attestation".
      const imports = [...code.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]);
      const requires = [...code.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]);
      for (const spec of [...imports, ...requires]) {
        expect(spec, `${file} imports forbidden module ${spec}`).to.not.match(/attestation|scripts[\\/]/);
      }
    }
  });

  it("keeps schema.ts a dependency-free leaf (no imports)", function () {
    const schema = sources.get("src/verifier/schema.ts")!;
    expect(schema, "schema.ts must have no import statements").to.not.match(/^\s*import\b/m);
    expect(schema, "schema.ts must have no require() calls").to.not.match(/\brequire\s*\(/);
  });

  it("only the verifier entry point depends on the PQ library", function () {
    // ml-dsa-65.ts is the single place that pulls in @noble/post-quantum; the
    // schema and result helpers stay free of crypto-library coupling.
    expect(sources.get("src/verifier/schema.ts")!).to.not.match(/@noble\/post-quantum/);
    expect(sources.get("src/verifier/result.ts")!).to.not.match(/@noble\/post-quantum/);
    expect(sources.get("src/verifier/evidence.ts")!).to.not.match(/@noble\/post-quantum/);
    expect(sources.get("src/verifier/ml-dsa-65.ts")!).to.match(/@noble\/post-quantum/);
  });
});
