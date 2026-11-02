/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — NOT PRODUCTION.
 *
 * THE AUTHORITY CENSUS OF THE ERC-20 SPEND PLANE, run by the REAL checker.
 *
 * `authority/check.ts` derives the external state-changing surface of
 * `VaultKernelPrototype` / `VaultKernelFactoryPrototype` from the compiled AST and
 * traces, per function, which of the four gate primitives is reached before the
 * first privileged effect; `authority-manifest.json` declares what each function
 * must reach. Both are keyed by CONTRACT NAME and SELECTOR. The candidates keep
 * every Generation-1 selector and change no authority primitive, so the honest
 * test is not a new manifest: it is the SAME checker with the SAME manifest run on
 * the candidate compiled under the Generation-1 names (an in-memory rename of the
 * sources and their keys, nothing on disk). If the plane had added a principal,
 * widened a mechanism or moved a gate after an effect, the Generation-1 manifest
 * would refuse it here.
 *
 * The Generation-1 census itself, from the Hardhat build-info, is the positive
 * control: the candidate must reproduce its verdicts row for row.
 */
import { expect } from "chai";

import { buildCompiledSources, type CompiledSources } from "../authority/ast.js";
import { discoverSurface } from "../authority/discover.js";
import { loadManifest, runCheck } from "../authority/check.js";
import { resolvePrimitiveIds } from "../authority/trace.js";
import {
  compilePlane,
  GEN1_FACTORY,
  GEN1_KERNEL,
  PLANE_FACTORY,
  VARIANT_A,
  VARIANT_B,
} from "../erc20-spend-plane/compile.js";

type Report = ReturnType<typeof runCheck>;

function compiledAs(variant: "A" | "B"): CompiledSources {
  const kernel = variant === "A" ? VARIANT_A : VARIANT_B;
  // Order matters: the longer variant-B name is renamed first so the variant-A name inside it is not mangled.
  const renames: Record<string, string> =
    variant === "A"
      ? { [VARIANT_A]: GEN1_KERNEL, [PLANE_FACTORY]: GEN1_FACTORY }
      : { [VARIANT_B]: GEN1_KERNEL, [PLANE_FACTORY]: GEN1_FACTORY };
  const compiled = compilePlane({ renames, ast: true });
  if (!compiled.asts) throw new Error("ast output was not produced");
  // The factory is typed against variant A; under the variant-B rename the kernel named VaultKernelPrototype is B
  // while the factory still references VaultKernelErc20Prototype (A). Both are present in the unit.
  void kernel;
  return buildCompiledSources(compiled.asts as Record<string, { ast: unknown }>);
}

function verdictMap(report: Report): Record<string, string> {
  const out: Record<string, string> = {};
  for (const row of report.rows) if (row.isStateChanging && row.verdict) out[row.key] = row.verdict;
  return out;
}

function failures(report: Report): string {
  return JSON.stringify(
    report.rows.filter((r) => r.verdict && r.verdict !== "PASS" && r.verdict !== "PASS_WITH_DECLARED_EXCEPTION"),
    null,
    2,
  );
}

describe("ERC-20 spend plane — authority census by the real checker", function () {
  this.timeout(180_000);

  const manifest = loadManifest();
  let gen1Report: Report;
  let reportA: Report;
  let reportB: Report;
  let compiledA: CompiledSources;
  let compiledB: CompiledSources;

  before(function () {
    // POSITIVE CONTROL: Generation 1 from the Hardhat build-info the CI job compiles first.
    gen1Report = runCheck({ manifest, skipProvenance: true });
    compiledA = compiledAs("A");
    compiledB = compiledAs("B");
    reportA = runCheck({ compiled: compiledA, manifest, skipProvenance: true });
    reportB = runCheck({ compiled: compiledB, manifest, skipProvenance: true });
  });

  it("positive control: the Generation-1 census passes with zero failures", function () {
    expect(gen1Report.summary.failed, failures(gen1Report)).to.equal(0);
    expect(gen1Report.summary.total).to.be.greaterThan(0);
  });

  it("variant A passes the Generation-1 manifest UNCHANGED: zero failures, zero unclassified, zero stale entries", function () {
    expect(reportA.summary.failed, failures(reportA)).to.equal(0);
    expect(reportA.summary.byVerdict["UNCLASSIFIED_EXTERNAL_STATE_CHANGE"] ?? 0).to.equal(0);
    expect(reportA.summary.byVerdict["STALE_MANIFEST_ENTRY"] ?? 0).to.equal(0);
  });

  it("variant B passes it too", function () {
    expect(reportB.summary.failed, failures(reportB)).to.equal(0);
    expect(reportB.summary.byVerdict["UNCLASSIFIED_EXTERNAL_STATE_CHANGE"] ?? 0).to.equal(0);
    expect(reportB.summary.byVerdict["STALE_MANIFEST_ENTRY"] ?? 0).to.equal(0);
  });

  it("the verdict per gated entry is IDENTICAL to Generation 1's, row for row", function () {
    expect(verdictMap(reportA)).to.deep.equal(verdictMap(gen1Report));
    expect(verdictMap(reportB)).to.deep.equal(verdictMap(gen1Report));
    expect(reportA.summary).to.deep.equal(gen1Report.summary);
  });

  it("execute still reaches HYBRID before its first effect, and its only unresolved shape is the declared policy-plane nesting", function () {
    for (const report of [reportA, reportB]) {
      const execute = report.rows.find((r) => r.key === "VaultKernelPrototype:6bc44090");
      expect(execute, "execute row missing").to.not.equal(undefined);
      expect(execute!.signature).to.equal("execute(address,uint256,uint256,uint64,bytes,bytes,bytes)");
      expect(execute!.observedMechanisms).to.deep.equal(["HYBRID"]);
      expect(execute!.observedOrderOk).to.equal(true);
      expect(execute!.verdict).to.equal("PASS_WITH_DECLARED_EXCEPTION");
      // The settlement block adds no unresolved statement of its own: every unresolved reason is the policy plane's.
      for (const reason of execute!.observedUnresolvedReasons ?? []) {
        expect(reason).to.match(/IfStatement|if/i);
      }
    }
  });

  it("the state-changing surface of the candidate kernel is the Generation-1 surface: same selectors, nothing added", function () {
    const surfaceOf = (compiled: CompiledSources) => {
      const kernelNode = (() => {
        for (const key of Object.keys(compiled.bySourceKey)) {
          const ast = compiled.bySourceKey[key].ast as { nodes: { nodeType: string; name: string }[] };
          const hit = ast.nodes.find((n) => n.nodeType === "ContractDefinition" && n.name === GEN1_KERNEL);
          if (hit) return hit;
        }
        throw new Error("kernel not found");
      })();
      const primitives = resolvePrimitiveIds(kernelNode);
      return discoverSurface(compiled, primitives, GEN1_KERNEL).filter((f) => f.isStateChanging);
    };
    // Keyed exactly as the checker keys them: kind for constructor/receive, the 4-byte selector for functions.
    const keyed = (rows: { kind: string; selector?: string; key?: string }[]) =>
      rows.map((r) => (r.kind === "function" ? `function:${r.selector ?? r.key!.split(":")[1]}` : r.kind)).sort();
    const gen1Rows = gen1Report.rows.filter(
      (r) => r.contract === GEN1_KERNEL && r.isStateChanging && r.verdict !== "STALE_MANIFEST_ENTRY",
    );
    const a = surfaceOf(compiledA);
    const b = surfaceOf(compiledB);
    expect(keyed(a)).to.deep.equal(keyed(gen1Rows));
    expect(keyed(b)).to.deep.equal(keyed(gen1Rows));

    // The AST-level signature text differs in exactly ONE place: execute's recipient is no longer
    // `address payable`, because the plane never sends native value to it. The selector is unchanged
    // (the ABI type is `address` either way), so no signing tooling changes.
    const textOf = (rows: { signature: string }[]) => rows.map((r) => r.signature).sort();
    const gen1Text = textOf(gen1Rows);
    for (const candidate of [a, b]) {
      const differing = textOf(candidate).filter((s) => !gen1Text.includes(s));
      expect(differing).to.deep.equal(["execute(address,uint256,uint256,uint64,bytes,bytes,bytes)"]);
      expect(gen1Text.filter((s) => !textOf(candidate).includes(s))).to.deep.equal([
        "execute(address payable,uint256,uint256,uint64,bytes,bytes,bytes)",
      ]);
    }
  });

  it("the new view admittedAsset() is discovered and is NOT state-changing, so no manifest entry is owed for it", function () {
    for (const report of [reportA, reportB]) {
      const row = report.rows.find((r) => r.signature === "admittedAsset()");
      expect(row, "admittedAsset() not discovered").to.not.equal(undefined);
      expect(row!.isStateChanging).to.equal(false);
      expect(row!.stateMutability).to.equal("view");
    }
  });

  it("variant B's genesis helper is internal and view: no new externally reachable surface", function () {
    const rows = reportB.rows.filter((r) => /GenesisVerifier/.test(r.signature));
    expect(rows).to.deep.equal([]);
  });
});
