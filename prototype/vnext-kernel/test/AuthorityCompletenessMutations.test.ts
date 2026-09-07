/**
 * PROVES the authority completeness checker (prototype/vnext-kernel/authority/)
 * actually detects the failure class it exists to prevent: a correct
 * authorization helper with a privileged path that bypasses it. Every
 * mutation here is applied to an IN-MEMORY COPY of the real source (see
 * authority/mutation-harness.ts) and compiled independently with raw solc --
 * nothing here ever writes to prototype/vnext-kernel/contracts/.
 *
 * THE VACUITY RULE (same as KernelPrototype.test.ts): a mutation test that
 * only shows "the mutant was rejected" proves nothing if the checker rejects
 * everything, or rejects it for an unrelated reason. Every `it` below
 * asserts the SPECIFIC verdict/reason expected for that mutation, and
 * `describe("baseline")` proves the unmutated tree is the positive control
 * every other test is a delta from.
 */
import { expect } from "chai";
import fs from "node:fs";
import type { CompiledSources } from "../authority/ast.js";
import { discoverSurface, traceDiscoveredFunction } from "../authority/discover.js";
import { compileMutatedKernel, insertBeforeFunction, replaceWithinFunction } from "../authority/mutation-harness.js";
import { runCheck, loadManifest, keyOf, type Manifest } from "../authority/check.js";
import { resolvePrimitiveIds } from "../authority/trace.js";

const KERNEL_SOURCE_PATH = "prototype/vnext-kernel/contracts/VaultKernelPrototype.sol";
const readKernelSource = () => fs.readFileSync(KERNEL_SOURCE_PATH, "utf8");

function findContract(compiled: CompiledSources, name: string) {
  for (const key of Object.keys(compiled.bySourceKey)) {
    const ast = compiled.bySourceKey[key].ast;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const hit = (ast.nodes as any[]).find((n) => n.nodeType === "ContractDefinition" && n.name === name);
    if (hit) return hit;
  }
  throw new Error(`contract not found: ${name}`);
}

function compileOrThrow(overrides: Record<string, string>) {
  const result = compileMutatedKernel(overrides);
  if (!result.ok) throw new Error(`mutation fixture failed to compile:\n${result.errors.join("\n")}`);
  return result.compiled;
}

const REAL_MANIFEST = loadManifest();

/** Runs the full check.ts pipeline against a mutated compile, using the REAL manifest by default (proving the mutation is caught against the actual declared model), or a supplied override manifest for tests that need a temporary entry for a fixture-only function. */
function checkMutation(overrides: Record<string, string>, manifest: Manifest = REAL_MANIFEST) {
  const compiled = compileOrThrow(overrides);
  return runCheck({ compiled, manifest, skipProvenance: true });
}

function rowFor(report: ReturnType<typeof runCheck>, key: string) {
  const row = report.rows.find((r) => r.key === key);
  if (!row) throw new Error(`no census row for key "${key}" -- available: ${report.rows.map((r) => r.key).join(", ")}`);
  return row;
}

const rotateCredentialCall = "_authorise(digest, ecdsaSig, pqSig, pqKey);";
const floorOnlyReplacement = "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();";

describe("Authority completeness checker — baseline (positive control)", function () {
  it("the unmutated kernel passes with zero failures", function () {
    const compiled = compileOrThrow({});
    const report = runCheck({ compiled, manifest: REAL_MANIFEST, skipProvenance: true });
    expect(report.summary.failed, JSON.stringify(report.rows.filter((r) => r.verdict && r.verdict !== "PASS" && r.verdict !== "PASS_WITH_DECLARED_EXCEPTION"), null, 2)).to.equal(0);
    expect(report.summary.pass).to.be.greaterThan(0);
  });
});

describe("PHASE 7 — historical bypass mutations (must FAIL)", function () {
  it("mutation A: rotateCredential HYBRID -> floor-only is rejected as a CREDENTIAL_REPLACEMENT regression", function () {
    const mutated = replaceWithinFunction(
      readKernelSource(),
      "rotateCredential",
      rotateCredentialCall,
      floorOnlyReplacement,
    );
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:b809c196");
    expect(row.verdict).to.equal("MECHANISM_MISMATCH");
    expect(row.reasons.join(" ")).to.match(/HYBRID/);
    expect(report.summary.failed).to.be.greaterThan(0);
  });

  it("mutation B: setVerifier HYBRID -> floor-only is rejected as a VERIFIER_REPLACEMENT regression", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(src, "setVerifier", "_authorise(digest, ecdsaSig, pqSig, pqKey);", floorOnlyReplacement);
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:35fae3fb");
    expect(row.verdict).to.equal("MECHANISM_MISMATCH");
    expect(row.reasons.join(" ")).to.match(/HYBRID/);
  });

  it("mutation C: setPolicy HYBRID -> floor-only is rejected as a POLICY_CHANGE regression", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(src, "setPolicy", "_authorise(digest, ecdsaSig, pqSig, pqKey);", floorOnlyReplacement);
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:5b704804");
    expect(row.verdict).to.equal("MECHANISM_MISMATCH");
    expect(row.reasons.join(" ")).to.match(/HYBRID/);
  });

  it("new-surface mutation: an unclassified new privileged function fails closed", function () {
    const src = readKernelSource();
    const mutated = insertBeforeFunction(
      src,
      "setPolicy",
      "    function emergencySetVerifier(address v) external {\n        pqVerifier = v;\n    }\n",
    );
    const compiled = compileOrThrow({ "VaultKernelPrototype.sol": mutated });
    const primitives = resolvePrimitiveIds(findContract(compiled, "VaultKernelPrototype"));
    const fns = discoverSurface(compiled, primitives, "VaultKernelPrototype");
    const newFn = fns.find((f) => f.name === "emergencySetVerifier");
    expect(newFn, "the new function must itself be discovered by AST surface discovery").to.not.be.undefined;

    const report = runCheck({ compiled, manifest: REAL_MANIFEST, skipProvenance: true });
    const key = keyOf(newFn!);
    const row = rowFor(report, key);
    expect(row.verdict).to.equal("UNCLASSIFIED_EXTERNAL_STATE_CHANGE");
  });

  it("renamed-bypass mutation: an innocuously-named new privileged function ALSO fails closed (not name-pattern matching)", function () {
    const src = readKernelSource();
    const mutated = insertBeforeFunction(
      src,
      "setPolicy",
      "    function updateVerifierConfiguration(address v) external {\n        pqVerifier = v;\n    }\n",
    );
    const compiled = compileOrThrow({ "VaultKernelPrototype.sol": mutated });
    const primitives = resolvePrimitiveIds(findContract(compiled, "VaultKernelPrototype"));
    const fns = discoverSurface(compiled, primitives, "VaultKernelPrototype");
    const newFn = fns.find((f) => f.name === "updateVerifierConfiguration")!;
    const report = runCheck({ compiled, manifest: REAL_MANIFEST, skipProvenance: true });
    expect(rowFor(report, keyOf(newFn)).verdict).to.equal("UNCLASSIFIED_EXTERNAL_STATE_CHANGE");
  });
});

describe("PHASE 8 — ordering (gate must precede effect, not merely be present)", function () {
  it("moving the state write before _authorise in setPolicy is rejected as an ORDER_VIOLATION", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(
      src,
      "setPolicy",
      "        _authorise(digest, ecdsaSig, pqSig, pqKey);\n        _consume(DOMAIN_CREDENTIAL, nonce, deadline);\n        policyEngine = policy;\n        emit PolicyChanged(policy);",
      "        policyEngine = policy;\n        emit PolicyChanged(policy);\n        _authorise(digest, ecdsaSig, pqSig, pqKey);\n        _consume(DOMAIN_CREDENTIAL, nonce, deadline);",
    );
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:5b704804");
    expect(row.verdict).to.equal("ORDER_VIOLATION");
  });
});

describe("PHASE 9 — authority-cut regression per outcome class (beyond the 3 historical ones)", function () {
  it("ASSET_MOVEMENT: weakening execute's HYBRID gate is rejected", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(src, "execute", rotateCredentialCall, floorOnlyReplacement);
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    expect(rowFor(report, "VaultKernelPrototype:6bc44090").verdict).to.equal("MECHANISM_MISMATCH");
  });

  it("GUARDIAN_CHANGE: removing setGuardians' quorum check is rejected", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(src, "setGuardians", "_requireQuorum(digest, proof);", "// AUTHORITY MUTATION: quorum check removed");
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:b19138b8");
    expect(row.verdict).to.equal("MECHANISM_MISMATCH");
    expect(row.reasons.join(" ")).to.match(/QUORUM/);
  });

  it("MIGRATION: removing bindMigration's credential half (keeping only quorum) is rejected", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(
      src,
      "bindMigration",
      "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      "// AUTHORITY MUTATION: credential half removed, quorum-only",
    );
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:bb0cea8a");
    expect(row.verdict).to.equal("MECHANISM_MISMATCH");
    expect(row.reasons.join(" ")).to.match(/FLOOR_ONLY/);
  });

  it("RECOVERY_COMPLETION: removing executeRecovery's possession-proof gate is rejected", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(
      src,
      "executeRecovery",
      "        _requireIncomingPossession(\n            recoveryPossessionDigest(),\n            r.proposedSigner,\n            r.proposedPqKeyHash,\n            r.proposedVerifier,\n            c\n        );\n",
      "        // AUTHORITY MUTATION: possession-proof check removed\n",
    );
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:bfd6b85c");
    expect(row.verdict).to.equal("MECHANISM_MISMATCH");
    expect(row.reasons.join(" ")).to.match(/POSSESSION_PROOF/);
  });
});

describe("PHASE 15 — adversarial self-review of the checker itself", function () {
  it("KILLED: routing an existing gate through a NEW internal view wrapper is still detected (transitive reachability)", function () {
    const src = readKernelSource();
    let mutated = insertBeforeFunction(
      src,
      "cancelRecovery",
      "    function _cancelGateWrapper(bytes32 d, bytes calldata s) internal view returns (bool) {\n        return _floorAuthorises(d, s);\n    }\n",
    );
    mutated = replaceWithinFunction(
      mutated,
      "cancelRecovery",
      "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      "if (!_cancelGateWrapper(digest, ecdsaSig)) revert BadSignature();",
    );
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:1271666a");
    // The wrapper is still recognised as reaching FLOOR_ONLY -- the refactor does not
    // fool the checker into losing sight of the gate.
    expect(row.verdict, JSON.stringify(row.reasons)).to.equal("PASS");
  });

  it("KILLED: an effect moved into a brand-new non-view internal helper is still classified EFFECT, not silently safe", function () {
    const src = readKernelSource();
    let mutated = insertBeforeFunction(
      src,
      "setPolicy",
      "    function _setPolicyEffect(address p) internal {\n        policyEngine = p;\n        emit PolicyChanged(p);\n    }\n",
    );
    mutated = replaceWithinFunction(mutated, "setPolicy", "policyEngine = policy;\n        emit PolicyChanged(policy);", "_setPolicyEffect(policy);");
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:5b704804");
    // Still correctly gated (HYBRID before the new helper's effect) -- proves the
    // non-view-call-is-EFFECT rule generalises to helpers the checker has never seen.
    expect(row.verdict, JSON.stringify(row.reasons)).to.equal("PASS");
  });

  it("KILLED: a modifier gating BEFORE the function body is recognised as satisfying the required mechanism", function () {
    const src = readKernelSource();
    let mutated = insertBeforeFunction(
      src,
      "setPolicy",
      '    modifier onlyHybridDirect(bytes32 digest, bytes calldata ecdsaSig, bytes calldata pqSig, bytes calldata pqKey) {\n        _authorise(digest, ecdsaSig, pqSig, pqKey);\n        _;\n    }\n\n    function viaModifierGate(\n        address policy,\n        bytes32 digest,\n        bytes calldata ecdsaSig,\n        bytes calldata pqSig,\n        bytes calldata pqKey\n    ) external onlyHybridDirect(digest, ecdsaSig, pqSig, pqKey) {\n        policyEngine = policy;\n        emit PolicyChanged(policy);\n    }\n',
    );
    const compiled = compileOrThrow({ "VaultKernelPrototype.sol": mutated });
    const primitives = resolvePrimitiveIds(findContract(compiled, "VaultKernelPrototype"));
    const fns = discoverSurface(compiled, primitives, "VaultKernelPrototype");
    const fn = fns.find((f) => f.name === "viaModifierGate")!;
    const trace = traceDiscoveredFunction(compiled, primitives, fn);
    expect(trace.mechanismsReached, JSON.stringify(trace)).to.include("HYBRID");
    expect(trace.mechanismsReachedAfterEffect).to.not.include("HYBRID");
  });

  it("KILLED: a modifier gating AFTER the function body (`_; then the check`) is NOT credited -- the effect is unguarded", function () {
    const src = readKernelSource();
    let mutated = insertBeforeFunction(
      src,
      "setPolicy",
      '    modifier fakeGateAfterBody(bytes32 digest, bytes calldata ecdsaSig, bytes calldata pqSig, bytes calldata pqKey) {\n        _;\n        _authorise(digest, ecdsaSig, pqSig, pqKey);\n    }\n\n    function viaFakeModifierGate(\n        address policy,\n        bytes32 digest,\n        bytes calldata ecdsaSig,\n        bytes calldata pqSig,\n        bytes calldata pqKey\n    ) external fakeGateAfterBody(digest, ecdsaSig, pqSig, pqKey) {\n        policyEngine = policy;\n        emit PolicyChanged(policy);\n    }\n',
    );
    const compiled = compileOrThrow({ "VaultKernelPrototype.sol": mutated });
    const primitives = resolvePrimitiveIds(findContract(compiled, "VaultKernelPrototype"));
    const fns = discoverSurface(compiled, primitives, "VaultKernelPrototype");
    const fn = fns.find((f) => f.name === "viaFakeModifierGate")!;
    const trace = traceDiscoveredFunction(compiled, primitives, fn);
    // The gate exists in the modifier, but only AFTER the placeholder -- it must not
    // count as satisfying the function's own (unguarded) effect.
    expect(trace.mechanismsReached, JSON.stringify(trace)).to.not.include("HYBRID");
  });

  it("KILLED (fails closed, not silently accepted): a hand-inlined equivalent of the floor check, never calling a named primitive, is rejected as a mismatch", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(
      src,
      "cancelRecovery",
      "if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();",
      "if (digest.recover(ecdsaSig) != ecdsaSigner) revert BadSignature();",
    );
    const report = checkMutation({ "VaultKernelPrototype.sol": mutated });
    const row = rowFor(report, "VaultKernelPrototype:1271666a");
    // DECLARED LIMITATION (see authority/README.md): the checker cannot prove this
    // inlined check is SEMANTICALLY equivalent to _floorAuthorises -- what it CAN and
    // does do is refuse to silently credit an authority mechanism that was not routed
    // through a named, audited primitive, which is why this still fails rather than
    // passing.
    expect(row.verdict, JSON.stringify(row.reasons)).to.equal("MECHANISM_MISMATCH");
  });

  it("KILLED: a new overload of an already-classified function name is its own unclassified selector", function () {
    const src = readKernelSource();
    const mutated = insertBeforeFunction(
      src,
      "setGuardians",
      "    function setPolicy(address policy, bool urgent) external {\n        policyEngine = policy;\n        emit PolicyChanged(policy);\n    }\n",
    );
    const compiled = compileOrThrow({ "VaultKernelPrototype.sol": mutated });
    const primitives = resolvePrimitiveIds(findContract(compiled, "VaultKernelPrototype"));
    const fns = discoverSurface(compiled, primitives, "VaultKernelPrototype");
    const overloads = fns.filter((f) => f.name === "setPolicy");
    expect(overloads.length).to.equal(2);
    const report = runCheck({ compiled, manifest: REAL_MANIFEST, skipProvenance: true });
    const newOverload = overloads.find((f) => f.signature.includes("bool"))!;
    expect(rowFor(report, keyOf(newOverload)).verdict).to.equal("UNCLASSIFIED_EXTERNAL_STATE_CHANGE");
    // The ORIGINAL overload must still be found and still pass -- proves selector-based
    // keying, not name-based, and that adding an overload does not corrupt the existing entry.
    const original = overloads.find((f) => !f.signature.includes("bool"))!;
    expect(rowFor(report, keyOf(original)).verdict).to.equal("PASS");
  });

  it("checker self-protection: an unresolvable loop construct in a privileged function is UNRESOLVED, not silently passed", function () {
    const src = readKernelSource();
    const mutated = replaceWithinFunction(
      src,
      "setPolicy",
      "policyEngine = policy;",
      "for (uint256 i; i < 1; ++i) { policyEngine = policy; }",
    );
    const compiled = compileOrThrow({ "VaultKernelPrototype.sol": mutated });
    const primitives = resolvePrimitiveIds(findContract(compiled, "VaultKernelPrototype"));
    const fns = discoverSurface(compiled, primitives, "VaultKernelPrototype");
    const fn = fns.find((f) => f.name === "setPolicy")!;
    const trace = traceDiscoveredFunction(compiled, primitives, fn);
    expect(trace.unresolved, JSON.stringify(trace)).to.equal(true);
    // And because the real manifest has no orderingExceptionReason for setPolicy, the
    // full checker must fail rather than silently pass an un-analysed loop.
    const report = runCheck({ compiled, manifest: REAL_MANIFEST, skipProvenance: true });
    expect(rowFor(report, "VaultKernelPrototype:5b704804").verdict).to.equal("UNRESOLVED_ORDERING_NO_EXCEPTION");
  });
});

describe("PHASE 12 — checker self-protection on the manifest itself", function () {
  it("a manifest entry with an unrecognized outcome fails closed rather than being ignored", function () {
    const manifest: Manifest = JSON.parse(JSON.stringify(REAL_MANIFEST));
    manifest.entries["VaultKernelPrototype:5b704804"].outcomes = ["NOT_A_REAL_OUTCOME"];
    const compiled = compileOrThrow({});
    const report = runCheck({ compiled, manifest, skipProvenance: true });
    expect(rowFor(report, "VaultKernelPrototype:5b704804").verdict).to.equal("MALFORMED_MANIFEST_ENTRY");
  });

  it("a manifest entry with an unrecognized mechanism fails closed rather than being ignored", function () {
    const manifest: Manifest = JSON.parse(JSON.stringify(REAL_MANIFEST));
    (manifest.entries["VaultKernelPrototype:5b704804"].expectedMechanisms as string[]) = ["NOT_A_REAL_MECHANISM"];
    const compiled = compileOrThrow({});
    const report = runCheck({ compiled, manifest, skipProvenance: true });
    expect(rowFor(report, "VaultKernelPrototype:5b704804").verdict).to.equal("MALFORMED_MANIFEST_ENTRY");
  });

  it("a stale manifest entry (function removed/renamed) is reported, not silently dropped", function () {
    const manifest: Manifest = JSON.parse(JSON.stringify(REAL_MANIFEST));
    manifest.entries["VaultKernelPrototype:deadbeef"] = {
      signature: "neverExisted()",
      outcomes: ["POLICY_CHANGE"],
      expectedMechanisms: ["HYBRID"],
      expectedCut: "min(2,k)",
      orderingExceptionReason: null,
      justification: "test fixture",
    };
    const compiled = compileOrThrow({});
    const report = runCheck({ compiled, manifest, skipProvenance: true });
    expect(rowFor(report, "VaultKernelPrototype:deadbeef").verdict).to.equal("STALE_MANIFEST_ENTRY");
  });
});
