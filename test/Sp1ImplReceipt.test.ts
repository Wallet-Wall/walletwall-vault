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
import { expect } from "chai";
import { readFileSync } from "node:fs";

import { SUPPORTED_DEPLOYMENT_CHAINS } from "../scripts/lib/sp1-chain-execution";
import { readDesignations } from "../scripts/lib/sp1-designation";
import {
  IMPL_RECEIPT_REL,
  STATUS_KEYS,
  STOP_CONDITION_IDS,
  compareReceipt,
  deriveImplReceipt,
  implReceiptErrors,
  probeHaltedIdentityElsewhere,
  probeIdentityReuse,
  probeOverrides,
  probeRpcFailClosed,
  productionBindingStatus,
  readImplReceiptInputs,
  serializeImplReceipt,
  type ImplReceiptInputs,
} from "../scripts/lib/sp1-impl-receipt";
import { readWrapperBuilds } from "../scripts/lib/sp1-wrapper-build";
import { planWrapperDeployment } from "../scripts/lib/zk-verifier-deployment";

describe("SP1 implementation lane — the implementation receipt", function () {
  this.timeout(300_000);
  const committed = () => JSON.parse(readFileSync(IMPL_RECEIPT_REL, "utf8"));
  let inputs: ImplReceiptInputs;

  before(function () {
    inputs = readImplReceiptInputs(".", committed().baseCommit);
  });

  const perturbed = (change: (i: ImplReceiptInputs) => void) => {
    const i = structuredClone(inputs);
    change(i);
    return deriveImplReceipt(i);
  };

  it("the committed receipt is exactly what the repository derives; an edited value is refused", function () {
    expect(implReceiptErrors(".")).to.deep.equal([]);
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
    const d1 = readDesignations(".")[0];
    const s = deriveImplReceipt(inputs).statuses;
    expect(s.SP1_DIRECT_VERIFIER_PIN.value).to.equal("CONSTRUCTOR_CODE_HASH_PIN");
    expect(s.SP1_VERIFIER_RUNTIME_HASH.value).to.equal(d1.verifier.runtimeCodeKeccak);
    expect(s.PROGRAM_IDENTITY_DECISION.value).to.equal("PINNED_VENDOR_BUILD");
    expect(s.PROGRAM_VKEY_DESIGNATION.value).to.equal(`${d1.id}: ${d1.programVKey}`);
    expect(s.CANONICAL_BUILD_STATUS.value).to.equal("REPRODUCED");
    expect(s.SUCCESSOR_DESIGNATION_STATUS.value).to.equal("SUCCESSOR_PATH_READY_NONE_DESIGNATED");
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
  });

  it("PRODUCTION_SP1_BINDING_STATUS is ESTABLISHED only when every prerequisite is met; this lane leaves five unmet", function () {
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
    const r = deriveImplReceipt(inputs);
    expect(r.stopConditions.map((c) => c.id)).to.deep.equal([...STOP_CONDITION_IDS]);
    expect(r.stopConditions.filter((c) => c.triggered)).to.deep.equal([]);
    expect(r.verdict).to.equal("BUILT_AND_TESTED_AWAITING_OWNER_REVIEW");
    const cases: [string, (i: ImplReceiptInputs) => void][] = [
      ["CANONICAL_BUILD_DOES_NOT_REPRODUCE", (i) => (i.canonical.oneHost = "PROCEDURE_DRIFT")],
      ["ONE_ELF_CONFLICTING_VKEYS", (i) => (i.canonical.conflictingVkeys = 1)],
      ["CHAINS_DISAGREE_ON_RUNTIME_IDENTITY", (i) => (i.chainExecution.codes = ["0x01", "0x02"])],
      ["PER_CHAIN_VERDICTS_DIVERGE", (i) => (i.chainExecution.verdictsAsRequired = false)],
      ["PIN_BYPASSABLE_VIA_GATEWAY_ROUTING", (i) => (i.ast.sp1CallTargets = ["gateway"])],
      ["PRODUCTION_VALUES_OVERRIDABLE", (i) => (i.probes.overrides[0].attackRefused = false)],
      ["REGISTRY_HISTORY_REWRITABLE_UNDETECTED", (i) => (i.registryErrors = ["shallow"])],
      ["HALTED_IDENTITY_REPUBLISHABLE_BY_ADDRESS_CHANGE", (i) => (i.probes.identityReuse.attackRefused = false)],
      ["CROSS_CHAIN_FIX_NEEDS_NEW_MUTABLE_PRINCIPAL", (i) => i.ast.mutatingFunctions.push("setRegistry")],
      ["F1_CHANGES_GUEST_ELF_VKEY_OR_PROOF_FORMAT", (i) => (i.designationErrors = ["subject"])],
      ["RPC_FAILURE_FAILS_OPEN", (i) => (i.probes.rpc.attackRefused = false)],
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

  it("cites tests that exist and carry the titles it names", function () {
    const r = deriveImplReceipt(inputs);
    for (const k of STATUS_KEYS) {
      for (const c of r.statuses[k].verifiedBy) {
        expect(readFileSync(c.test, "utf8"), `${k}: ${c.test}`).to.include(`it("${c.title}"`);
      }
    }
  });
});
