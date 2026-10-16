/**
 * SP1 implementation lane: the implementation receipt (scripts/lib/sp1-impl-receipt.ts,
 * evidence/zk/sp1-impl/implementation-receipt.json).
 *
 * Every status is computed from the repository (the compiled wrapper's AST and ABI, the generated records and their
 * validators, the measured observations) and from executing the lane's own decision functions on probes, each refusal
 * paired with its positive control. The committed receipt must be exactly what the repository derives, the lane's STOP
 * conditions are evaluated from the same inputs, and PRODUCTION_SP1_BINDING_STATUS is ESTABLISHED only when every
 * prerequisite is met — which nothing this lane produces does.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { expect } from "chai";

import { SUPPORTED_DEPLOYMENT_CHAINS } from "../scripts/lib/sp1-chain-execution";
import { readDesignations } from "../scripts/lib/sp1-designation";
import {
  IMPL_RECEIPT_REL,
  STATUS_KEYS,
  STOP_CONDITION_IDS,
  baseCommitErrors,
  baseDriftErrors,
  compareReceipt,
  deriveImplReceipt,
  implReceiptErrors,
  probeHaltedIdentityElsewhere,
  probeIdentityReuse,
  probeFinalityReads,
  probeOverrides,
  probeRegistryHistory,
  probeRpcFailClosed,
  productionBindingStatus,
  readImplReceiptInputs,
  receiptCommit,
  rulesetInput,
  serializeImplReceipt,
  wrapperAstFacts,
  type ImplReceiptInputs,
} from "../scripts/lib/sp1-impl-receipt";
import { compiledWrapper, readWrapperBuilds, walkAst } from "../scripts/lib/sp1-wrapper-build";
import { MAIN_RULESET_OBSERVATION_REL } from "../scripts/lib/main-ruleset";
import type { Provider } from "ethers";
import { planWrapperDeployment } from "../scripts/lib/zk-verifier-deployment";
import { skipWhenInstrumented } from "./helpers/instrumented";

describe("SP1 implementation lane — the implementation receipt", function () {
  this.timeout(300_000);
  const committed = () => JSON.parse(readFileSync(IMPL_RECEIPT_REL, "utf8"));
  let inputs: ImplReceiptInputs;

  before(async function () {
    inputs = await readImplReceiptInputs(".", committed().baseCommit);
  });

  const perturbed = (change: (i: ImplReceiptInputs) => void) => {
    const i = structuredClone(inputs);
    change(i);
    return deriveImplReceipt(i);
  };

  it("the committed receipt is exactly what the repository derives; an edited value is refused", async function () {
    skipWhenInstrumented(this);
    expect(await implReceiptErrors(".")).to.deep.equal([]);
    const derived = deriveImplReceipt(inputs);
    const edited = structuredClone(derived);
    edited.statuses.PROVING_AVAILABILITY.value = "ESTABLISHED";
    expect(compareReceipt(serializeImplReceipt(derived), derived)).to.deep.equal([]);
    expect(compareReceipt(serializeImplReceipt(edited), derived).join("\n")).to.match(
      /not what the repository derives/,
    );
  });

  it("states every status the lane returns, in order, each with its basis", function () {
    const r = deriveImplReceipt(inputs);
    expect(Object.keys(r.statuses)).to.deep.equal([...STATUS_KEYS]);
    for (const k of STATUS_KEYS) {
      expect(r.statuses[k].value, k).to.be.a("string").that.is.not.empty;
      expect(r.statuses[k].basis, k).to.be.an("array").that.is.not.empty;
    }
  });

  it("derives the values the evidence supports", function () {
    skipWhenInstrumented(this);
    const d1 = readDesignations(".")[0];
    const s = deriveImplReceipt(inputs).statuses;
    expect(s.SP1_DIRECT_VERIFIER_PIN.value).to.equal("CONSTRUCTOR_CODE_HASH_PIN");
    expect(s.SP1_VERIFIER_RUNTIME_HASH.value).to.equal(d1.verifier.runtimeCodeKeccak);
    expect(s.PROGRAM_IDENTITY_DECISION.value).to.equal("PINNED_VENDOR_BUILD");
    expect(s.PROGRAM_VKEY_DESIGNATION.value).to.equal(`${d1.id}: ${d1.programVKey}`);
    expect(s.CANONICAL_BUILD_STATUS.value).to.equal("REPRODUCED");
    expect(s.SUCCESSOR_DESIGNATION_STATUS.value).to.equal("PROGRAM_REBUILD_SUCCESSORS_ONLY_NONE_DESIGNATED");
    expect(s.REGISTRY_APPEND_ONLY_STATUS.value).to.equal("APPEND_ONLY_ON_FULL_HISTORY");
    expect(s.REGISTRY_BUILD_PROVENANCE_STATUS.value).to.equal("BUILD_RECORDED_PER_FACT");
    expect(s.CROSS_CHAIN_HALTED_IDENTITY_STATUS.value).to.equal("REPOSITORY_PUBLISHED_HALT_REFUSED_ON_EVERY_CHAIN");
    expect(s.PER_CHAIN_EXECUTION_CHECK.value).to.equal("PASSED");
    expect(s.F1_CHAIN_ID_FIX.value).to.equal("FULL_WIDTH_WRAPPER_ONLY");
    expect(s.TD2_HALT_INVARIANTS_PRESERVED.value).to.equal("PRESERVED");
    expect(s.MULTISIG_AUTHORIZATION_CLASS_PRESERVED.value).to.equal(
      "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL",
    );
    expect(s.PROVING_AVAILABILITY.value).to.equal("OWNER_DOWNLOAD_REQUIRED");
    expect(s.PRODUCTION_SP1_BINDING_STATUS.value).to.equal("NOT_ESTABLISHED");
  });

  it("each status follows its evidence: a perturbed input changes it", function () {
    expect(perturbed((i) => (i.ast.constructorPinsCodehash = false)).statuses.SP1_DIRECT_VERIFIER_PIN.value).to.equal(
      "NOT_PINNED",
    );
    expect(perturbed((i) => (i.buildErrors = ["drift"])).statuses.SP1_DIRECT_VERIFIER_PIN.value).to.equal("NOT_PINNED");
    expect(perturbed((i) => (i.ast.chainIdNarrowings = 1)).statuses.F1_CHAIN_ID_FIX.value).to.equal("TRUNCATING");
    expect(
      perturbed((i) => (i.ast.journalTypes = ["bytes32", "bytes32", "bytes32", "uint256", "address"])).statuses
        .F1_CHAIN_ID_FIX.value,
    ).to.equal("PROOF_FORMAT_CHANGED");
    expect(perturbed((i) => (i.chainExecution.errors = ["x"])).statuses.PER_CHAIN_EXECUTION_CHECK.value).to.equal(
      "FAILED",
    );
    expect(perturbed((i) => (i.registryErrors = ["x"])).statuses.REGISTRY_APPEND_ONLY_STATUS.value).to.equal(
      "VIOLATED",
    );
    expect(
      perturbed((i) => i.contractsChanged.push({ path: "contracts/WalletWallVault.sol", status: "M" })).statuses
        .TD2_HALT_INVARIANTS_PRESERVED.value,
    ).to.equal("CHANGED_OUTSIDE_THE_WRAPPER");
    expect(
      perturbed((i) => (i.probes.haltedIdentity.registry.attackRefused = false)).statuses
        .CROSS_CHAIN_HALTED_IDENTITY_STATUS.value,
    ).to.equal("NOT_REFUSED");
    // A refusal whose positive control also failed proves nothing.
    expect(
      perturbed((i) => (i.probes.haltedIdentity.deployPlan.controlAccepted = false)).statuses
        .CROSS_CHAIN_HALTED_IDENTITY_STATUS.value,
    ).to.equal("NOT_REFUSED");
    expect(
      perturbed((i) => (i.proving.status = "LOCAL_COPY_NOT_ARCHIVED")).statuses.PROVING_AVAILABILITY.value,
    ).to.equal("LOCAL_COPY_NOT_ARCHIVED");
    expect(
      perturbed((i) => (i.td2.multisigClass = "AUTHORITY_NEUTRAL")).statuses.MULTISIG_AUTHORIZATION_CLASS_PRESERVED
        .value,
    ).to.equal("CHANGED");
    expect(
      perturbed((i) => (i.td2.errors = ["the TD2 record does not validate"])).statuses.TD2_HALT_INVARIANTS_PRESERVED
        .value,
      "an invalid record is no demonstration either way",
    ).to.equal("TD2_RECORD_INVALID");
  });

  it("reads the pin and F-1 from the compiler's AST: another stored target, or a narrowed block.chainid, is seen", function () {
    const { abi, contract } = compiledWrapper(".");
    const plain = wrapperAstFacts(contract, abi);
    expect([plain.constructorPinsCodehash, plain.chainIdNarrowings]).to.deep.equal([true, 0]);
    // The constructor still checks the target's code hash, but stores another value as SP1_VERIFIER.
    const storesOther = structuredClone(contract);
    walkAst(storesOther, (n) => {
      if (n.nodeType === "Assignment" && n.leftHandSide?.name === "SP1_VERIFIER") {
        n.rightHandSide = { ...n.rightHandSide, name: "_programVKey" };
      }
    });
    expect(wrapperAstFacts(storesOther, abi).constructorPinsCodehash).to.equal(false);
    // verify() converts block.chainid to a narrower type somewhere.
    const narrowed = structuredClone(contract);
    narrowed.nodes
      .find((n: { name?: string }) => n.name === "verify")
      .body.statements.unshift({
        nodeType: "ExpressionStatement",
        expression: {
          nodeType: "FunctionCall",
          kind: "typeConversion",
          typeDescriptions: { typeString: "uint64" },
          arguments: [
            { nodeType: "MemberAccess", memberName: "chainid", expression: { nodeType: "Identifier", name: "block" } },
          ],
        },
      });
    expect(wrapperAstFacts(narrowed, abi).chainIdNarrowings).to.equal(1);
  });

  it("main's ruleset as the receipt reads it: gaps only from a well-formed record, errors from a missing one", function () {
    const committedRuleset = JSON.parse(readFileSync(MAIN_RULESET_OBSERVATION_REL, "utf8"));
    expect(rulesetInput(committedRuleset)).to.deep.equal({
      observedAtUtc: committedRuleset.observedAtUtc,
      errors: [],
      gaps: [],
    });
    const forcePushes = structuredClone(committedRuleset);
    forcePushes.response.rules = forcePushes.response.rules.filter(
      (r: { type: string }) => r.type !== "non_fast_forward",
    );
    expect(rulesetInput(forcePushes).gaps.join("\n")).to.match(/force pushes/);
    expect(rulesetInput(null)).to.deep.include({ gaps: [] });
    expect(rulesetInput(null).errors.join("\n")).to.match(/no observation/);
    const malformed = { ...structuredClone(committedRuleset), schema: "x" };
    expect(rulesetInput(malformed).errors).to.not.deep.equal([]);
    expect(rulesetInput(malformed).gaps, "a malformed record shows no gaps: it shows nothing").to.deep.equal([]);
  });

  it("the rebuild evidence: only identity drift is the STOP; drift of procedure, an incomplete build or invalid evidence is no reproduction, and no STOP (L-4, F3)", function () {
    const stop1 = (r: ReturnType<typeof deriveImplReceipt>) =>
      r.stopConditions.find((c) => c.id === "CANONICAL_BUILD_DOES_NOT_REPRODUCE")!.triggered;
    const twoHosts = (r: ReturnType<typeof deriveImplReceipt>) =>
      r.productionBinding.prerequisites.find((p) => p.id === "CANONICAL_RELEASE_REBUILD_TWO_HOSTS")!.met;
    for (const verdict of ["PROCEDURE_DRIFT", "INCOMPLETE", "INSUFFICIENT_HOSTS"]) {
      const r = perturbed((i) => (i.canonical.oneHost = verdict));
      expect(r.statuses.CANONICAL_BUILD_STATUS.value, verdict).to.equal(verdict);
      expect(stop1(r), `${verdict} is no STOP`).to.equal(false);
    }
    expect(
      stop1(perturbed((i) => (i.canonical.twoHost = "PROGRAM_IDENTITY_DRIFT"))),
      "drift on either reading",
    ).to.equal(true);
    // A two-host rebuild that reproduces counts only from valid evidence (re-derived, bound to this tree's tools).
    expect(twoHosts(perturbed((i) => (i.canonical.twoHost = "REPRODUCED"))), "the positive control").to.equal(true);
    const invalid = perturbed((i) => {
      i.canonical.twoHost = "REPRODUCED";
      i.canonical.evidenceErrors = ["the observation is not what this tree's checker derives"];
    });
    expect(invalid.statuses.CANONICAL_BUILD_STATUS.value).to.equal("EVIDENCE_INVALID");
    expect(invalid.statuses.CANONICAL_BUILD_STATUS.basis.join("\n")).to.include(
      "is not what this tree's checker derives",
    );
    expect(twoHosts(invalid)).to.equal(false);
    // The release rebuild is of the latest designation, the one CI holds HEAD to (the re-review's A6).
    const superseded = perturbed((i) => {
      i.canonical.twoHost = "REPRODUCED";
      i.canonical.designation = "mldsa65-withdrawal-d0";
    });
    expect(twoHosts(superseded), "a superseded designation's rebuild").to.equal(false);
    expect(
      superseded.productionBinding.prerequisites.find((p) => p.id === "CANONICAL_RELEASE_REBUILD_TWO_HOSTS")!.basis,
    ).to.match(/not the latest designation/);
  });

  it("a STOP is raised only from valid records; invalid evidence is EVIDENCE_INVALID, never a STOP (the re-review's L2)", function () {
    skipWhenInstrumented(this);
    const triggered = (r: ReturnType<typeof deriveImplReceipt>) =>
      r.stopConditions.filter((c) => c.triggered).map((c) => c.id);
    // Drift read from rebuild evidence that does not re-derive is no demonstration.
    const unproven = perturbed((i) => {
      i.canonical.oneHost = "PROGRAM_IDENTITY_DRIFT";
      i.canonical.conflictingVkeys = 1;
      i.canonical.evidenceErrors = ["the observation is not what this tree's checker derives"];
    });
    expect(triggered(unproven)).to.deep.equal([]);
    expect(unproven.verdict).to.equal("EVIDENCE_INVALID: CANONICAL_REBUILD");
    // A designation that does not regenerate is invalid evidence; a subject that is not the designation's is a change.
    const invalidDesignation = perturbed((i) => (i.designationErrors = ["mldsa65-withdrawal-d1 does not regenerate"]));
    expect(triggered(invalidDesignation)).to.deep.equal([]);
    expect(invalidDesignation.verdict).to.equal("EVIDENCE_INVALID: DESIGNATIONS");
    const guestChanged = perturbed((i) => {
      i.subjectErrors = ["the zkvm guest tree at HEAD is not mldsa65-withdrawal-d1's"];
      i.designationErrors = [...i.subjectErrors];
    });
    expect(triggered(guestChanged)).to.deep.equal(["F1_CHANGES_GUEST_ELF_VKEY_OR_PROOF_FORMAT"]);
    // An unmeasured ruleset reads unmeasured, never as protection.
    const unmeasured = perturbed((i) => (i.ruleset = { observedAtUtc: "", errors: ["no observation"], gaps: [] }));
    expect(unmeasured.verdict).to.equal("EVIDENCE_INVALID: RULESET");
    const basis = unmeasured.stopConditions.find((c) => c.id === "REGISTRY_HISTORY_REWRITABLE_UNDETECTED")!.basis;
    expect(basis).to.match(/unmeasured/);
    expect(basis).to.not.match(/protected by its ruleset[^;]*: yes/);
    expect(unmeasured.statuses.REGISTRY_APPEND_ONLY_STATUS.basis.join("\n")).to.match(/unmeasured/);
  });

  it("PRODUCTION_SP1_BINDING_STATUS is ESTABLISHED only when every prerequisite is met; this lane leaves five unmet", function () {
    skipWhenInstrumented(this);
    const r = deriveImplReceipt(inputs);
    expect(r.productionBinding.prerequisites.filter((p) => !p.met).map((p) => p.id)).to.deep.equal([
      "CANONICAL_RELEASE_REBUILD_TWO_HOSTS",
      "REGISTERED_ACTIVE_WRAPPER",
      "REAL_WALLETWALL_PROOF",
      "PROVING_AVAILABILITY",
      "OWNER_REVIEW_AND_MERGE",
    ]);
    const all = r.productionBinding.prerequisites.map((p) => ({ ...p, met: true }));
    expect(productionBindingStatus(all)).to.equal("ESTABLISHED");
    all.forEach((_, k) => {
      expect(productionBindingStatus(all.map((p, j) => ({ ...p, met: j !== k })))).to.equal("NOT_ESTABLISHED");
    });
    expect(r.realValue.blocked).to.equal(true);
  });

  it("evaluates every STOP condition from the same inputs: none is triggered, and a perturbed input triggers its own", function () {
    skipWhenInstrumented(this);
    const r = deriveImplReceipt(inputs);
    expect(r.stopConditions.map((c) => c.id)).to.deep.equal([...STOP_CONDITION_IDS]);
    expect(r.stopConditions.filter((c) => c.triggered)).to.deep.equal([]);
    expect(r.verdict).to.equal("BUILT_AND_TESTED_AWAITING_OWNER_REVIEW");
    const cases: [string, (i: ImplReceiptInputs) => void][] = [
      ["CANONICAL_BUILD_DOES_NOT_REPRODUCE", (i) => (i.canonical.oneHost = "PROGRAM_IDENTITY_DRIFT")],
      ["ONE_ELF_CONFLICTING_VKEYS", (i) => (i.canonical.conflictingVkeys = 1)],
      [
        "ONE_ELF_CONFLICTING_VKEYS",
        (i) =>
          i.designationErrors.push("designations a and b: one ELF maps to two vkeys (PROGRAM_IDENTITY_CONTRADICTION)"),
      ],
      ["CHAINS_DISAGREE_ON_RUNTIME_IDENTITY", (i) => (i.chainExecution.codes = ["0x01", "0x02"])],
      ["PER_CHAIN_VERDICTS_DIVERGE", (i) => (i.chainExecution.verdictsAsRequired = false)],
      ["PIN_BYPASSABLE_VIA_GATEWAY_ROUTING", (i) => (i.ast.sp1CallTargets = ["gateway"])],
      ["PRODUCTION_VALUES_OVERRIDABLE", (i) => (i.probes.overrides[0].attackRefused = false)],
      ["REGISTRY_HISTORY_REWRITABLE_UNDETECTED", (i) => (i.probes.registryHistory.attackRefused = false)],
      ["REGISTRY_HISTORY_REWRITABLE_UNDETECTED", (i) => (i.probes.registryHistory.controlAccepted = false)],
      [
        "REGISTRY_HISTORY_REWRITABLE_UNDETECTED",
        (i) => (i.ruleset.gaps = ["force pushes to main are not refused (no non_fast_forward rule)"]),
      ],
      ["HALTED_IDENTITY_REPUBLISHABLE_BY_ADDRESS_CHANGE", (i) => (i.probes.identityReuse.attackRefused = false)],
      ["CROSS_CHAIN_FIX_NEEDS_NEW_MUTABLE_PRINCIPAL", (i) => i.ast.mutatingFunctions.push("setRegistry")],
      [
        "F1_CHANGES_GUEST_ELF_VKEY_OR_PROOF_FORMAT",
        (i) => (i.subjectErrors = ["the zkvm guest tree at HEAD is not mldsa65-withdrawal-d1's"]),
      ],
      ["RPC_FAILURE_FAILS_OPEN", (i) => (i.probes.rpc.attackRefused = false)],
      ["RPC_FAILURE_FAILS_OPEN", (i) => (i.probes.finality[0].attackRefused = false)],
      ["RPC_FAILURE_FAILS_OPEN", (i) => (i.probes.finality[1].attackRefused = false)],
      ["TD2_INVARIANTS_WEAKENED", (i) => (i.ast.haltSetsOnlyTrue = false)],
      ["BYTECODE_EXCEEDS_BUDGET", (i) => (i.sizes[0].withinLimit = false)],
    ];
    for (const [id, change] of cases) {
      const stopped = perturbed(change);
      expect(
        stopped.stopConditions.filter((c) => c.triggered).map((c) => c.id),
        id,
      ).to.include(id);
      expect(stopped.verdict, id).to.match(/^STOP:/);
    }
  });

  it("a finalized-block read that fails, or names no block, is never read as a block to observe at (L-7)", async function () {
    const probes = await probeFinalityReads();
    expect(probes).to.have.length(2);
    for (const p of probes) expect(p, p.probe).to.deep.include({ controlAccepted: true, attackRefused: true });
    const refusals = probes.map((p) => p.refusal).join(" | ");
    expect(refusals).to.match(/503/);
    expect(refusals).to.match(/no finalized block/);
    // The probes see a broken read: one that falls back to the latest block, and one that never answers.
    const latestInstead = async (provider: Provider) => {
      await provider.getBlock("finalized"); // a failure still throws
      const b = (await provider.getBlock("latest"))!;
      return { block: b.number, blockHash: String(b.hash) };
    };
    expect((await probeFinalityReads(latestInstead))[0], "reads the latest block").to.deep.include({
      controlAccepted: false,
    });
    const alwaysFails = async () => {
      throw new Error("server response 503 Service Unavailable");
    };
    const [failing] = await probeFinalityReads(alwaysFails);
    expect(failing, "a read that never answers is no control").to.deep.include({
      controlAccepted: false,
      attackRefused: true,
    });
  });

  it("the verdict is gated on valid evidence: a STOP outranks invalid records, which outrank BUILT_AND_TESTED (F6)", function () {
    skipWhenInstrumented(this);
    const records = (r: ReturnType<typeof deriveImplReceipt>) =>
      r.productionBinding.prerequisites.find((p) => p.id === "RECORDS_VALID")!.met;
    const cases: [string, (i: ImplReceiptInputs) => void][] = [
      ["TD1_RECEIPT", (i) => (i.td1.errors = ["x"])],
      ["TD2_RECORD", (i) => (i.td2.errors = ["x"])],
      ["WRAPPER_BUILDS", (i) => (i.buildErrors = ["x"])],
      ["REGISTRY", (i) => (i.registryErrors = ["x"])],
      ["CHAIN_EXECUTION", (i) => (i.chainExecution.errors = ["x"])],
      ["CANONICAL_REBUILD", (i) => (i.canonical.evidenceErrors = ["x"])],
      ["PROVING", (i) => (i.proving.errors = ["x"])],
      ["RULESET", (i) => (i.ruleset.errors = ["x"])],
    ];
    for (const [source, change] of cases) {
      const r = perturbed(change);
      expect(r.verdict, source).to.equal(`EVIDENCE_INVALID: ${source}`);
      expect(records(r), source).to.equal(false);
    }
    const both = perturbed((i) => {
      i.td1.errors = ["x"];
      i.probes.registryHistory.attackRefused = false;
    });
    expect(both.verdict).to.equal("STOP: REGISTRY_HISTORY_REWRITABLE_UNDETECTED");
    expect(both.productionBinding.prerequisites.find((p) => p.id === "NO_STOP_TRIGGERED")!.met).to.equal(false);
    const clean = deriveImplReceipt(inputs);
    expect(records(clean)).to.equal(true);
    expect(clean.productionBinding.prerequisites.find((p) => p.id === "NO_STOP_TRIGGERED")!.met).to.equal(true);
  });

  it("names the prerequisites no evidence in this lane can meet: PRODUCTION_SP1_BINDING_STATUS cannot be ESTABLISHED here (F6)", function () {
    const r = deriveImplReceipt(inputs);
    expect(r.productionBinding.prerequisites.filter((p) => !p.reachableInThisLane).map((p) => p.id)).to.deep.equal([
      "REAL_WALLETWALL_PROOF",
      "PROVING_AVAILABILITY",
      "OWNER_REVIEW_AND_MERGE",
    ]);
    for (const p of r.productionBinding.prerequisites.filter((x) => !x.reachableInThisLane)) {
      expect(p.met, p.id).to.equal(false);
      expect(p.basis, p.id).to.match(/lane/);
    }
  });

  it("the probes run the lane's own decision functions, each refusal paired with its positive control", function () {
    const ds = readDesignations(".");
    const builds = readWrapperBuilds(".");
    const overrides = probeOverrides(planWrapperDeployment, ds, builds);
    expect(overrides).to.have.length(3 * SUPPORTED_DEPLOYMENT_CHAINS.length);
    for (const p of overrides) expect(p, p.probe).to.deep.include({ controlAccepted: true, attackRefused: true });
    const halted = probeHaltedIdentityElsewhere(ds, builds);
    expect(halted.registry).to.deep.include({ controlAccepted: true, attackRefused: true });
    expect(halted.deployPlan).to.deep.include({ controlAccepted: true, attackRefused: true });
    expect(probeIdentityReuse(ds)).to.deep.include({ controlAccepted: true, attackRefused: true });
    expect(probeRpcFailClosed()).to.deep.include({ controlAccepted: true, attackRefused: true });
    // STOP 7 rests on the history walk itself, run on a throwaway repository: an append passes, a dropped halt does not.
    expect(probeRegistryHistory(ds, builds)).to.deep.include({ controlAccepted: true, attackRefused: true });
    expect(probeRegistryHistory(ds, builds).refusal).to.match(/removed or rewrote a published fact/);
    // A decision function that refuses everything fails its control: its refusals prove nothing.
    const refuseAll = (() => {
      throw new Error("no override exists anywhere");
    }) as unknown as typeof planWrapperDeployment;
    for (const p of probeOverrides(refuseAll, ds, builds)) expect(p.controlAccepted).to.equal(false);
  });

  it("reads the pin, F-1 and the halt from the compiler's AST of the wrapper", function () {
    expect(inputs.ast).to.deep.include({
      constructorPinsCodehash: true,
      chainIdNarrowings: 0,
      chainIdComparedFullWidth: true,
      haltSetsOnlyTrue: true,
      verifyChecksHaltFirst: true,
    });
    expect(inputs.ast.verifyExternalCalls).to.deep.equal([
      "contract ISP1Verifier.verifyProof",
      "contract ZKMLDSAVerifier.decodeProofPayload",
    ]);
    expect(inputs.ast.sp1CallTargets).to.deep.equal(["SP1_VERIFIER"]);
    expect(inputs.ast.journalTypes).to.deep.equal(["bytes32", "bytes32", "bytes32", "uint64", "address"]);
    expect(inputs.ast.mutatingFunctions).to.deep.equal(["halt"]);
    expect(inputs.ast.immutables).to.deep.equal({
      SP1_VERIFIER: "immutable",
      PROGRAM_VKEY: "immutable",
      HALT_PRINCIPAL: "immutable",
    });
    expect(inputs.contractsChanged).to.deep.equal([
      { path: "contracts/mocks/ChainIdBindingProbe.sol", status: "A" },
      { path: "contracts/verifiers/ZKMLDSAVerifier.sol", status: "M" },
    ]);
  });

  it("reads the same facts from an instrumented AST: coverage probes are discounted, a look-alike call is not", function () {
    const { abi, contract } = compiledWrapper(".");
    const plain = wrapperAstFacts(contract, abi);
    const probe = (base = "__NomicFoundationCoverage") => ({
      nodeType: "ExpressionStatement",
      expression: {
        nodeType: "FunctionCall",
        arguments: [],
        expression: {
          nodeType: "MemberAccess",
          memberName: "sendHit",
          expression: { nodeType: "Identifier", name: base },
        },
      },
    });
    const instrument = (base?: string) => {
      const c = structuredClone(contract);
      const verify = c.nodes.find((n: { name?: string }) => n.name === "verify");
      const first = verify.body.statements[0];
      first.trueBody = { nodeType: "Block", statements: [probe(base), first.trueBody] };
      verify.body.statements.unshift(probe(base));
      return wrapperAstFacts(c, abi);
    };
    expect(instrument()).to.deep.equal(plain);
    expect(plain.verifyChecksHaltFirst).to.equal(true);
    expect(instrument("Telemetry").verifyChecksHaltFirst, "a call an author wrote is not a probe").to.equal(false);
  });

  it("cites tests that exist and carry the titles it names", function () {
    const r = deriveImplReceipt(inputs);
    for (const k of STATUS_KEYS) {
      for (const c of r.statuses[k].verifiedBy) {
        expect(readFileSync(c.test, "utf8"), `${k}: ${c.test}`).to.include(`it("${c.title}"`);
      }
    }
  });

  describe("after main moves, what the receipt states against its base must hold against the newer main (the re-review's A2)", function () {
    // main: m0 (vault A, wrapper w0) - m1 (docs) - m2 (vault B); the lane forks at m0 and changes the wrapper (l1).
    const VAULT = "contracts/WalletWallVault.sol";
    const WRAPPER = "contracts/verifiers/ZKMLDSAVerifier.sol";
    let repo: string;
    const ids: Record<string, string> = {};
    const git = (...args: string[]) =>
      execFileSync(
        "git",
        ["-c", "core.autocrlf=false", "-c", "user.email=t@example.invalid", "-c", "user.name=t", ...args],
        {
          cwd: repo,
          encoding: "utf8",
        },
      ).trim();
    const commit = (name: string, files: Record<string, string>) => {
      for (const [rel, text] of Object.entries(files)) {
        mkdirSync(dirname(join(repo, rel)), { recursive: true });
        writeFileSync(join(repo, rel), text);
      }
      git("add", "-A");
      git("commit", "-q", "-m", name);
      ids[name] = git("rev-parse", "HEAD");
    };
    beforeEach(function () {
      repo = mkdtempSync(join(tmpdir(), "sp1-receipt-drift-"));
      git("init", "-q", "-b", "main");
      commit("m0", { [VAULT]: "vault A\n", [WRAPPER]: "wrapper w0\n" });
      git("checkout", "-q", "-b", "lane");
      commit("l1", { [IMPL_RECEIPT_REL]: "receipt\n", [WRAPPER]: "wrapper w1\n" });
      git("checkout", "-q", "main");
      commit("m1", { "docs/notes.md": "notes\n" });
      commit("m2", { [VAULT]: "vault B\n" });
      git("update-ref", "refs/remotes/origin/main", ids.m2);
      git("checkout", "-q", "lane");
    });
    afterEach(function () {
      rmSync(repo, { recursive: true, force: true });
    });

    it("a lane that merged a main commit touching no contract keeps its base (the positive control)", function () {
      git("merge", "-q", "--no-ff", "-m", "sync docs", ids.m1);
      expect(baseDriftErrors(repo, ids.m0)).to.deep.equal([]);
    });

    it("a lane that merged main's contract change and reverted it is refused: the old base would hide the revert", function () {
      git("merge", "-q", "--no-ff", "-m", "sync vault", ids.m2);
      commit("l3", { [VAULT]: "vault A\n" });
      expect(git("diff", "--name-only", ids.l1, "HEAD", "--", "contracts"), "the contracts are l1's again").to.equal(
        "",
      );
      expect(baseDriftErrors(repo, ids.m0).join("\n")).to.match(
        new RegExp(`against ${ids.m2}, the latest main commit in HEAD's history`),
      );
      expect(baseDriftErrors(repo, ids.m2), "the receipt generated again, against m2").to.deep.equal([]);
    });

    it("a journal main changed is drift too, though the contracts read the same against both commits", function () {
      rmSync(repo, { recursive: true, force: true });
      repo = mkdtempSync(join(tmpdir(), "sp1-receipt-journal-drift-"));
      git("init", "-q", "-b", "main");
      commit("c0", { [VAULT]: "vault A\n", [WRAPPER]: "abi.decode(publicValues, (uint64))\n// w0\n" });
      git("checkout", "-q", "-b", "lane");
      commit("l1", { [IMPL_RECEIPT_REL]: "receipt\n", [WRAPPER]: "abi.decode(publicValues, (uint64))\n// lane\n" });
      git("checkout", "-q", "main");
      commit("c1", { [WRAPPER]: "abi.decode(publicValues, (uint32))\n// w0\n" });
      git("update-ref", "refs/remotes/origin/main", ids.c1);
      git("checkout", "-q", "lane");
      try {
        git("merge", "-q", "-m", "sync", ids.c1);
      } catch {
        // the wrappers conflict: keep the lane's
      }
      commit("sync", { [WRAPPER]: "abi.decode(publicValues, (uint64))\n// lane\n" });
      expect(git("rev-list", "--parents", "-n", "1", "HEAD").split(" ")).to.have.length(3);
      expect(baseDriftErrors(repo, ids.c0).join("\n")).to.match(
        new RegExp(`against ${ids.c1}, the latest main commit in HEAD's history`),
      );
    });

    it("on main itself the commit that wrote the receipt decides (baseCommitErrors), not HEAD's history", function () {
      git("checkout", "-q", "--detach", ids.m2);
      git("merge", "-q", "--no-ff", "-m", "merge the lane", "lane");
      git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"));
      expect(baseDriftErrors(repo, ids.m0)).to.deep.equal([]);
    });
  });

  describe("the base is verified, never self-asserted (review finding F5)", function () {
    // main: m0 - m1 - m2 (first parent); the lane forks at m1, writes the receipt at l1, then l2; main moves to m2.
    let repo: string;
    const ids: Record<string, string> = {};
    const git = (...args: string[]) =>
      execFileSync("git", ["-c", "core.autocrlf=false", ...args], { cwd: repo, encoding: "utf8" }).trim();
    const commit = (name: string, rel: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), `${name}\n`);
      git("add", "-A");
      git("-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-q", "-m", name);
      ids[name] = git("rev-parse", "HEAD");
    };
    before(function () {
      repo = mkdtempSync(join(tmpdir(), "sp1-receipt-base-"));
      git("init", "-q", "-b", "main");
      commit("m0", "README.md");
      commit("m1", "contracts/A.sol");
      git("checkout", "-q", "-b", "lane");
      commit("l1", IMPL_RECEIPT_REL);
      commit("l2", "contracts/B.sol");
      git("checkout", "-q", "main");
      commit("m2", "docs/notes.md");
      git("update-ref", "refs/remotes/origin/main", ids.m2);
      git("checkout", "-q", "lane");
    });
    after(function () {
      rmSync(repo, { recursive: true, force: true });
    });

    it("the fork point is the base, though main has moved on; the receipt's commit is the one that wrote it", function () {
      expect(receiptCommit(repo)).to.equal(ids.l1);
      expect(baseCommitErrors(repo, ids.m1, receiptCommit(repo))).to.deep.equal([]);
    });

    it("refuses a lane commit as the base (P9: a base chosen to hide a change)", function () {
      expect(baseCommitErrors(repo, ids.l1, receiptCommit(repo)).join("\n")).to.match(/no commit of origin\/main/);
    });

    it("refuses an older main commit than the latest one in the receipt's history (a base chosen to hide a revert)", function () {
      expect(baseCommitErrors(repo, ids.m0, receiptCommit(repo)).join("\n")).to.match(
        new RegExp(`not the latest main commit .*${ids.m1} is later`),
      );
    });

    it("refuses a base HEAD does not descend from, and a base that is no full commit id", function () {
      expect(baseCommitErrors(repo, ids.m2, receiptCommit(repo)).join("\n")).to.match(/not an ancestor of HEAD/);
      expect(baseCommitErrors(repo, "m1", receiptCommit(repo)).join("\n")).to.match(/full commit id/);
    });

    it("holds at the pull request's synthetic merge, and on main after the merge", function () {
      git("checkout", "-q", "--detach", ids.m2);
      git("-c", "user.email=test@example.invalid", "-c", "user.name=test", "merge", "-q", "--no-ff", "-m", "M", "lane");
      try {
        expect(receiptCommit(repo), "the merge leaves the receipt as the lane wrote it").to.equal(ids.l1);
        expect(baseCommitErrors(repo, ids.m1, receiptCommit(repo))).to.deep.equal([]);
        git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"));
        expect(baseCommitErrors(repo, ids.m1, receiptCommit(repo)), "merged into main").to.deep.equal([]);
      } finally {
        git("update-ref", "refs/remotes/origin/main", ids.m2);
        git("checkout", "-q", "lane");
      }
    });

    it("a lane that merged main must regenerate: the receipt written before the merge has the old base", function () {
      git("checkout", "-q", "-b", "synced", "lane");
      git(
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=test",
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "sync",
        "main",
      );
      try {
        commit("l3", IMPL_RECEIPT_REL);
        expect(receiptCommit(repo)).to.equal(ids.l3);
        expect(baseCommitErrors(repo, ids.m1, ids.l3).join("\n")).to.match(new RegExp(`${ids.m2} is later`));
        expect(baseCommitErrors(repo, ids.m2, ids.l3)).to.deep.equal([]);
      } finally {
        git("checkout", "-q", "lane");
      }
    });

    it("after a squash merge of a lane brought up to date, the squash commit's receipt holds against its first parent", function () {
      // The ruleset requires a branch to be up to date: the lane synced at m2 and wrote its receipt again (l3, base m2).
      git("checkout", "-q", "--detach", ids.m2);
      git("merge", "-q", "--squash", "synced");
      git("-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-q", "-m", "S");
      const squash = git("rev-parse", "HEAD");
      git("update-ref", "refs/remotes/origin/main", squash);
      try {
        expect(receiptCommit(repo), "the squash commit wrote the receipt on main").to.equal(squash);
        expect(baseCommitErrors(repo, ids.m2, squash)).to.deep.equal([]);
        expect(baseCommitErrors(repo, ids.m1, squash).join("\n")).to.match(new RegExp(`${ids.m2} is later`));
      } finally {
        git("update-ref", "refs/remotes/origin/main", ids.m2);
        git("checkout", "-q", "lane");
      }
    });

    it("an uncommitted receipt is judged at HEAD, and without origin/main nothing is judged (fail closed)", function () {
      writeFileSync(join(repo, IMPL_RECEIPT_REL), "regenerated\n");
      try {
        expect(receiptCommit(repo)).to.equal(ids.l2);
      } finally {
        git("checkout", "-q", "--", IMPL_RECEIPT_REL);
      }
      git("update-ref", "-d", "refs/remotes/origin/main");
      try {
        expect(baseCommitErrors(repo, ids.m1, ids.l1).join("\n")).to.match(/origin\/main is not available/);
      } finally {
        git("update-ref", "refs/remotes/origin/main", ids.m2);
      }
    });
  });
});
