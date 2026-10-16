/**
 * SP1-TD2 — the consumers of the verifier as they stand after TD2 (a source scan of the working tree, the TD2
 * counterpart of SP1-TD1's scan of its own subject in test/Sp1Td1TrustTargetProbes.test.ts).
 *
 * What it pins: every contract that verifies through an IPQCVerifier, how each leaves a halted wrapper, and that
 * every rotating consumer wires the on-chain guard into the same five places (constructor, ownership transfer,
 * propose, apply, and the halted-identity record before the switch). WalletWallMultiSigVault now rotates with the
 * repository's delay (TD2-MULTISIG-ROTATION); it is still not a credential source for the policy bridge, and the
 * halt's scope still excludes it until the owner admits it (scripts/lib/verifier-binding.ts reads that scope).
 * A change to any of this is a change to what TD2 vouches for, and fails here first.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { expect } from "chai";

import { findContract, findFunctionDefinition, loadSourceAst, walkAst, type AstNode } from "./helpers/solidityAst";

const solidity = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? e.name === "mocks"
        ? []
        : solidity(join(dir, e.name))
      : e.name.endsWith(".sol")
        ? [join(dir, e.name).split("\\").join("/")]
        : [],
  );

const SOURCES = solidity("contracts").map((path) => ({ path, source: readFileSync(path, "utf8") }));
const contractName = (s: string) => /^contract\s+(\w+)/m.exec(s)?.[1];

describe("SP1-TD2 consumer scan (the working tree)", function () {
  // The same classification SP1-TD1 used, applied to today's tree.
  const consumers = SOURCES.filter(
    (f) => /\.verify\(/.test(f.source) && !/\bcontract\s+\w+\s+is\s+[^{]*\bIPQCVerifier\b/.test(f.source),
  ).map((f) => ({ name: contractName(f.source)!, path: f.path, source: f.source }));
  const rotates = (s: string) =>
    /function proposePQVerifier\([^)]*\)[^{;]*\bonlyOwner\b/.test(s) &&
    /function applyPQVerifierUpdate\([^)]*\)[^{;]*\bonlyOwner\b/.test(s) &&
    /PQ_VERIFIER_UPDATE_DELAY/.test(s);
  const follows = (s: string) => /\)\.pqVerifier\(\)/.test(s);
  const names = (keep: (s: string) => boolean) =>
    consumers
      .filter((c) => keep(c.source))
      .map((c) => c.name)
      .sort();
  const ROTATING = ["StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"];

  it("the four consumers: three rotate with the repository's 172,800 s delay, the bridge follows its consumer, none is fixed", function () {
    expect(names(() => true)).to.deep.equal([
      "PolicyControlBridge",
      "StablecoinVaultSimulator",
      "WalletWallMultiSigVault",
      "WalletWallVault",
    ]);
    expect(names(rotates)).to.deep.equal(ROTATING);
    expect(names(follows)).to.deep.equal(["PolicyControlBridge"]);
    expect(names((s) => !rotates(s) && !follows(s))).to.deep.equal([]);
    for (const c of consumers.filter((x) => rotates(x.source))) {
      expect(/\bPQ_VERIFIER_UPDATE_DELAY\s*=\s*2 days;/.test(c.source), `${c.name}: 2 days`).to.equal(true);
      expect(/\bGOVERNANCE_GRACE_PERIOD\s*=\s*14 days;/.test(c.source), `${c.name}: 14 days`).to.equal(true);
    }
  });

  it("the multisig vault's owner now holds the rotation as well as the pause (new authorization, accounted in the TD2 doc)", function () {
    const multisig = consumers.find((c) => c.name === "WalletWallMultiSigVault")!.source;
    const ownerOnly = [...multisig.matchAll(/function\s+(\w+)\s*\([^)]*\)[^{;]*\bonlyOwner\b/g)]
      .map((m) => m[1])
      .sort();
    expect(ownerOnly).to.deep.equal([
      "applyPQVerifierUpdate",
      "cancelPQVerifierUpdate",
      "pause",
      "proposePQVerifier",
      "unpause",
    ]);
  });

  it("the bridge still reads verifiers only from contracts that keep policyControlEpoch, and the multisig vault is not one", function () {
    const credentialSources = SOURCES.filter((f) =>
      /mapping\s*\([^;]*\)\s*public\b[^;=]*\bpolicyControlEpoch\s*;|function\s+policyControlEpoch\s*\([^)]*\)[^;{]*\{/.test(
        f.source,
      ),
    )
      .map((f) => contractName(f.source)!)
      .sort();
    expect(credentialSources).to.deep.equal(["StablecoinVaultSimulator", "WalletWallVault"]);
    expect(credentialSources.every((s) => ROTATING.includes(s))).to.equal(true);
  });

  /** The VerifierRotationGuard functions a function body calls, in source order. */
  function guardCalls(fn: AstNode): string[] {
    const calls: string[] = [];
    walkAst(fn, (n) => {
      if (n.nodeType !== "FunctionCall") return;
      const callee = n.expression as AstNode;
      if (callee?.nodeType === "MemberAccess" && (callee.expression as AstNode)?.name === "VerifierRotationGuard") {
        calls.push(String(callee.memberName));
      }
    });
    return calls;
  }

  for (const name of ROTATING) {
    it(`${name} wires the guard into its constructor, ownership transfer, propose and apply (and records before it switches)`, function () {
      const path = consumers.find((c) => c.name === name)!.path;
      const contract = findContract(loadSourceAst(path), name);
      const ctor = (contract.nodes as AstNode[]).find(
        (n) => n.nodeType === "FunctionDefinition" && n.kind === "constructor",
      )!;
      expect(guardCalls(ctor), "constructor").to.deep.equal(["requireNotHaltPrincipal"]);
      expect(guardCalls(findFunctionDefinition(contract, "_transferOwnership")), "_transferOwnership").to.deep.equal([
        "requireNotHaltPrincipal",
      ]);
      expect(guardCalls(findFunctionDefinition(contract, "proposePQVerifier")), "propose").to.deep.equal([
        "requireAdmissibleRotation",
      ]);
      const apply = findFunctionDefinition(contract, "applyPQVerifierUpdate");
      expect(guardCalls(apply), "apply").to.deep.equal(["requireAdmissibleRotation", "recordHaltedIdentity"]);
      // The record and the check happen before pqVerifier is reassigned.
      const order: string[] = [];
      walkAst(apply, (n) => {
        if (n.nodeType === "FunctionCall" && (n.expression as AstNode)?.expression?.name === "VerifierRotationGuard") {
          order.push(`guard@${String(n.src).split(":")[0]}`);
        }
        if (n.nodeType === "Assignment" && (n.leftHandSide as AstNode)?.name === "pqVerifier") {
          order.push(`assign@${String(n.src).split(":")[0]}`);
        }
      });
      const offsets = order.map((o) => [o.split("@")[0], Number(o.split("@")[1])] as const);
      const assign = offsets.find(([k]) => k === "assign")![1];
      expect(offsets.filter(([k]) => k === "guard").every(([, at]) => at < assign)).to.equal(true);
    });
  }

  it("every SP1 wrapper in the production contracts is haltable: no verifier on the SP1 path without the halt", function () {
    const sp1Wrappers = SOURCES.filter(
      (f) => /\bISP1Verifier\(/.test(f.source) && /\bcontract\s+\w+\s+is\s+[^{]*\bIPQCVerifier\b/.test(f.source),
    );
    expect(sp1Wrappers.map((f) => contractName(f.source))).to.deep.equal(["ZKMLDSAVerifier"]);
    for (const f of sp1Wrappers) expect(/\bis\s+[^{]*\bIHaltableVerifier\b/.test(f.source), f.path).to.equal(true);
  });
});
