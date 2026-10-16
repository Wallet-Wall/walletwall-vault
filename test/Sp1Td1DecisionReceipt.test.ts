/**
 * Tests for the SP1-TD1 decision receipt (scripts/lib/sp1-td1-decision.ts, evidence/zk/sp1-td1/): the committed
 * receipt re-derives from its inputs and observations (any hand edit is drift); the derivations respond to the
 * facts they consume (positive and negative controls); and the lane rules reject, on the receipt alone, the
 * over-claims they name — a self-consistent edit of derived facts the rules cannot re-run (pins, the equivalence
 * and widening claims, the authority delta) is caught by the re-derivation.
 *
 * Pure, fast, static reads — no SP1 toolchain, no proving, no network. The probe facts themselves are executed
 * by test/Sp1Td1TrustTargetProbes.test.ts.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  INHERITED_BY_EVERY_OPTION,
  REQUIRED_CHAIN_VERDICTS,
  TD1_CLAIM_KEYS,
  TD1_INPUTS_REL,
  TD1_RECEIPT_REL,
  boundMeasurementHashes,
  buildDecisionReceipt,
  checkContextFresh,
  decideTrustTarget,
  expectedChainCalls,
  readDecisionContext,
  validateCommittedDecisionReceipt,
  validateDecisionRules,
  type DecisionContext,
  type Td1ClaimKey,
  type Td1DecisionReceipt,
} from "../scripts/lib/sp1-td1-decision";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
let CTX: DecisionContext;
const ctx = (): DecisionContext => clone(CTX);
const committed = (): Td1DecisionReceipt =>
  JSON.parse(readFileSync(resolve(TD1_RECEIPT_REL), "utf8")) as Td1DecisionReceipt;
const built = (c = ctx()) => buildDecisionReceipt(c);
const option = (r: Td1DecisionReceipt, id: string) => r.options.find((o) => o.id === id)!;
const rulesOf = (r: Td1DecisionReceipt) => validateDecisionRules(r);
const expectRule = (r: Td1DecisionReceipt, fragment: string) =>
  expect(
    rulesOf(r).some((e) => e.includes(fragment)),
    `expected a rule error containing "${fragment}" in ${JSON.stringify(rulesOf(r))}`,
  ).to.equal(true);

const VENDOR_VKEY = "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc";
const VENDOR_ELF = "2adddae753011fb08e30127e38befe99c0092c956e01bf4486ca81827a632d8a";
const LOCAL_VKEY = "0x00eea6d622ce8cddee6387d922090de9710f844a977332a36c22c2651d040597";
const LOCAL_ELF = "ce057748f2f26b308e400835218280ed817758d62acaf1330800f2aa2a66513a";
const PAUSE =
  "WalletWall's own pauses, one per consumer of the verifier: each WalletWallVault, WalletWallMultiSigVault and StablecoinVaultSimulator deployment's owner-held pause() (gating its PQ-verifying entrypoints) and the PolicyControlBridge's one-way pause() (EMERGENCY_PAUSER) — liveness only; manual, several holders";

describe("SP1-TD1 decision receipt", function () {
  before(function () {
    CTX = readDecisionContext();
  });

  describe("the committed receipt", function () {
    it("re-derives exactly from its inputs, observations and the zkvm subject, and passes every rule", function () {
      expect(validateCommittedDecisionReceipt(committed(), ctx())).to.deep.equal([]);
      expect(rulesOf(built())).to.deep.equal([]);
    });

    it("records the decisions this lane reached", function () {
      const r = committed();
      expect(r.verdict).to.equal("DESIGN_DECIDED");
      expect(r.decisions.SP1_TRUST_TARGET_DECISION).to.equal("DIRECT_IMMUTABLE_VERIFIER");
      expect(r.decisions.SP1_TRUST_TARGET_OPTION).to.equal("A");
      expect(r.decisions.PROGRAM_IDENTITY_DECISION).to.equal("PINNED_VENDOR_BUILD");
      expect(r.decisions.PROGRAM_VKEY_DESIGNATION.vkey).to.equal(VENDOR_VKEY);
      expect(r.decisions.PROGRAM_VKEY_DESIGNATION.elfSha256).to.equal(VENDOR_ELF);
      expect(r.decisions.UPGRADE_MODEL).to.equal("EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION");
      expect(r.decisions.CROSS_CHAIN_MODEL).to.equal("CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK");
      expect(r.decisions.DEFECT_RESPONSE_COUPLING.status).to.equal("DECIDED");
      expect(r.decisions.DEFECT_RESPONSE_COUPLING.decision).to.equal("WALLETWALL_DETECT_AND_FAIL_CLOSED");
      expect([
        r.decisions.DEFECT_RESPONSE_MECHANISM,
        r.decisions.AUTHORIZATION_AUTHORITY_DELTA.classification,
        r.decisions.LIVENESS_AUTHORITY_DELTA.classification,
        r.decisions.HALT_REVERSIBILITY,
        r.decisions.RECOVERY,
        r.decisions.UPSTREAM_GATEWAY_OWNER,
        r.decisions.REAL_VALUE_BLOCKER,
      ]).to.deep.equal([
        "LOCAL_ONE_WAY_VERIFIER_HALT",
        "NO_NEW_AUTHORIZATION_PRINCIPAL",
        "WALLETWALL_EMERGENCY_HALT_PRINCIPAL_ADDED_HALT_ONLY",
        "ONE_WAY",
        // The owner's amendment: recovery is not claimed for the multisig vault, which cannot rotate (TD1-N11).
        "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE",
        "NOT_A_WALLETWALL_AUTHORITY",
        "TD2_IMPLEMENTATION_NOT_YET_BUILT",
      ]);
      const rot = (consumer: string, route: string, rotationDelaySeconds: number | null) => ({
        consumer,
        route,
        rotationDelaySeconds,
      });
      expect(r.decisions.DEFECT_RESPONSE_COUPLING.recoveryByConsumer).to.deep.equal([
        { ...rot("PolicyControlBridge", "ITS_CONSUMERS_TIMELOCKED_ROTATION", null), halt: "APPLIED", gate: null },
        { ...rot("StablecoinVaultSimulator", "OWN_TIMELOCKED_ROTATION", 172_800), halt: "APPLIED", gate: null },
        {
          ...rot("WalletWallMultiSigVault", "NONE", null),
          halt: "EXCLUDED_UNTIL_RECOVERABLE",
          gate: "TD2-MULTISIG-ROTATION",
        },
        { ...rot("WalletWallVault", "OWN_TIMELOCKED_ROTATION", 172_800), halt: "APPLIED", gate: null },
      ]);
      // The narrowing is the owner's, on record, and so is the keeping of the review's two additions.
      expect(r.decisions.DEFECT_RESPONSE_COUPLING.amendments.map((a) => [a.id, a.by, a.on])).to.deep.equal([
        ["TD1-N11-PREREQUISITE", "owner", "2026-10-15"],
        ["TD1-REVIEW-ADDITIONS-KEPT", "owner", "2026-10-15"],
      ]);
      // The rotation TD2 would give the multisig vault's owner is new authority, on the record before it is built.
      expect(r.decisions.AUTHORIZATION_AUTHORITY_DELTA.proposedForTd2).to.deep.equal([
        {
          principal: "WALLETWALL_MULTISIG_VAULT_OWNER",
          capabilities: ["PQ_VERIFIER_ROTATION"],
          classification: "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL",
          status: "PROPOSED_FOR_TD2",
        },
      ]);
      expect(r.decisions.REAL_VALUE_REQUIREMENTS).to.deep.equal(["TD2-COMMON-VERIFIER-HALT", "TD2-MULTISIG-ROTATION"]);
      // The decision closes the design question; it lifts nothing: real value waits for TD2.
      expect(r.decisions.REAL_PROOF_LANE_UNBLOCKED.value).to.equal(true);
      expect(r.decisions.IMPLEMENTATION_REQUIRED.required).to.equal(true);
    });

    it("refuses drift: any edit to the committed receipt is detected", function () {
      const r = committed();
      r.options[0].label += " (edited)";
      expect(validateCommittedDecisionReceipt(r, ctx())).to.include(
        "committed decision receipt has drifted from the generator; run `npm run sp1-td1:receipt`",
      );
    });

    it("refuses stale evidence: an observation whose bytes moved", function () {
      const c = ctx();
      c.fileHashes["evidence/zk/sp1-td1/observations/chain-state.raw.json"] = "0".repeat(64);
      expect(checkContextFresh(c).some((e) => e.includes("chain-state.raw.json"))).to.equal(true);
    });

    it("refuses a moved subject: a guest change without a new designation", function () {
      const c = ctx();
      c.workingTreeManifest[0].sha256 = "f".repeat(64);
      expect(checkContextFresh(c).some((e) => e.includes("a guest change needs a new designation"))).to.equal(true);
    });

    it("refuses an inputs file that does not list exactly the TD1 observations", function () {
      const c = ctx();
      c.inputs.evidence.td1Observations.pop();
      expect(checkContextFresh(c)).to.include("decision inputs must list exactly the TD1 observation files");
    });

    it("refuses a checkout whose HEAD records other zkvm trees than the subject, or none", function () {
      expect(CTX.gitTrees).to.deep.equal({
        guest: CTX.inputs.subject.zkvmGuestTree,
        host: CTX.inputs.subject.zkvmHostTree,
      });
      const c1 = ctx();
      c1.gitTrees.guest = "0".repeat(40);
      expect(checkContextFresh(c1)).to.include(
        `stale: HEAD:zkvm/guest is ${"0".repeat(40)}, not the subject's ${CTX.inputs.subject.zkvmGuestTree}`,
      );
      const c2 = ctx();
      c2.gitTrees.host = null;
      expect(checkContextFresh(c2)).to.include(
        `stale: HEAD:zkvm/host is null, not the subject's ${CTX.inputs.subject.zkvmHostTree}`,
      );
    });

    it("binds each committed measurement input to the hash its observation recorded", function () {
      const files = CTX.inputs.evidence.measurementFiles;
      expect(files.map((m) => [m.path, CTX.boundHashes[m.path]])).to.deep.equal(files.map((m) => [m.path, m.sha256]));
      const [script] = files;
      const c1 = ctx();
      c1.boundHashes[script.path] = "0".repeat(64);
      expect(checkContextFresh(c1).some((e) => e.startsWith(`unbound: ${script.path} (`))).to.equal(true);
      const c2 = ctx();
      c2.inputs.evidence.measurementFiles[0].boundTo.observation = c2.inputs.evidence.sp1p1Receipt.path;
      expect(checkContextFresh(c2)).to.include(
        `unbound: ${script.path} is bound to ${c2.inputs.evidence.sp1p1Receipt.path}, which is not a TD1 observation`,
      );
      // The bytes on disk are part of the evidence set like every observation.
      const c3 = ctx();
      c3.fileHashes[script.path] = "0".repeat(64);
      expect(checkContextFresh(c3).some((e) => e.startsWith(`stale: ${script.path} on disk`))).to.equal(true);
      expect(built().evidence.files.map((f) => f.path)).to.include.members(files.map((m) => m.path));
    });

    it("records a pointer that resolves to nothing, to a non-string, or through a missing step, as unbound", function () {
      const path = CTX.inputs.evidence.measurementFiles[0].path;
      for (const pointer of ["/scripts/missing.sh", "/scripts", "/nope/deeper", "scripts/remap-build.sh"]) {
        const c = ctx();
        c.inputs.evidence.measurementFiles[0].boundTo.pointer = pointer;
        c.boundHashes = boundMeasurementHashes(c.inputs);
        expect(c.boundHashes[path], pointer).to.equal(null);
        expect(
          checkContextFresh(c).some((e) => e.startsWith(`unbound: ${path} (`)),
          pointer,
        ).to.equal(true);
      }
      // Positive control: the recorded pointer resolves to the script's hash.
      expect(boundMeasurementHashes(CTX.inputs)[path]).to.equal(CTX.inputs.evidence.measurementFiles[0].sha256);
    });
  });

  describe("trust target: derivations respond to the facts", function () {
    it("separates authorization from liveness: the pinned gateway keeps only the owner's freeze", function () {
      const r = built();
      const b = option(r, "B");
      expect(b.widen.filter((l) => !l.governed)).to.deep.equal([]);
      expect(b.disable.map((l) => l.lever)).to.deep.equal(["freezeRoute", "freezeRoute"]);
      expect(b.upstreamGovernanceDependency).to.equal("liveness");
      const d = option(r, "D");
      expect(d.widen.filter((l) => !l.governed).map((l) => l.lever)).to.deep.equal(["addRoute", "addRoute"]);
      expect(d.upstreamGovernanceDependency).to.equal("authorization");
    });

    it("names the measured owners per chain: Safe 2-of-3 on Ethereum and Base, one EOA on both testnets", function () {
      const d = option(built(), "D");
      const owners = d.widen.filter((l) => !l.governed).map((l) => [l.principal, l.chains.join("+")]);
      expect(owners).to.deep.equal([
        [
          "upstream gateway owner 0xCafEf00d348Adbd57c37d1B77e0619C6244C6878 (Safe 1.3.0 2-of-3 (0 modules, no guard))",
          "1+8453",
        ],
        ["upstream gateway owner 0xBaB2c2aF5b91695e65955DA60d63aD1b2aE81126 (EOA (single key))", "11155111+84532"],
      ]);
    });

    it("ranks by authority minimisation: A over the viable options that carry external liveness levers", function () {
      const r = built();
      expect(["A", "AF", "B"].map((id) => option(r, id).viable)).to.deep.equal([true, true, true]);
      expect(decideTrustTarget(r.options)).to.deep.equal({ decision: "DIRECT_IMMUTABLE_VERIFIER", optionId: "A" });
      // Positive controls for the tie-breaks: without A, the freeze coupling (same liveness principals, shorter
      // path) is the decision; without both, the pinned gateway.
      expect(decideTrustTarget(r.options.filter((o) => o.id !== "A"))).to.deep.equal({
        decision: "DIRECT_IMMUTABLE_VERIFIER",
        optionId: "AF",
      });
      expect(decideTrustTarget(r.options.filter((o) => o.id !== "A" && o.id !== "AF"))).to.deep.equal({
        decision: "SELECTOR_PINNED_GATEWAY",
        optionId: "B",
      });
    });

    it("a selector-only pin is rejected because of the squat; without the squat fact it would pass (control)", function () {
      expect(option(built(), "B0").viable).to.equal(false);
      const c = ctx();
      c.inputs.probeFacts.B0_selectorOnlyPin.routeSquatOnUnroutedChainAccepted = false;
      expect(option(built(c), "B0").viable).to.equal(true);
    });

    it("the pinned gateway loses viability when its route can be replaced", function () {
      const c = ctx();
      c.inputs.probeFacts.B_selectorRouteCodePinned.pinnedRouteReplaceable = true;
      const b = option(built(c), "B");
      expect(b.viable).to.equal(false);
      expect(b.acceptedRelationMutableOutsideTimelock).to.equal(true);
    });

    it("a WalletWall-governed gateway is rejected: its admin widens with zero delay", function () {
      const c = option(built(), "C");
      expect(c.viable).to.equal(false);
      expect(c.widen.find((l) => l.lever === "gatewayAdminAddRoute")?.delaySeconds).to.equal(0);
      expect(c.requiresRedeployToUpgrade).to.equal(false);
      // Its admin's freeze is dual-use like upstream's: a liveness lever that also fails closed on a defect.
      expect(c.defectResponse).to.deep.equal([
        PAUSE,
        "WalletWall gateway admin via gatewayAdminFreezeRoute (fail-closed at once, at the holder's discretion)",
      ]);
    });

    it("a verifier runtime with a reachable state write is not an immutable target: nothing is decided", function () {
      const c = ctx();
      c.inputs.probeFacts.verifierRuntime.v610ForbiddenOpcodes = ["SSTORE"];
      const r = built(c);
      expect(r.trustTarget.established).to.equal(false);
      expect(r.decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
      expect(r.decisions.REAL_PROOF_LANE_UNBLOCKED.value).to.equal(false);
      expect(rulesOf(r)).to.deep.equal([]);
    });

    it("code identity needs one code hash on every chain", function () {
      const c = ctx();
      c.chain.chains["84532"].verifiers["v6.1.0"].codeKeccak = `0x${"ab".repeat(32)}`;
      const r = built(c);
      expect(r.trustTarget.established).to.equal(false);
      expect(r.trustTarget.failures.some((f) => f.includes("differs across chains"))).to.equal(true);
      expect(r.decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
    });

    it("code identity needs CREATE2-authenticated initcode and second-provider corroboration", function () {
      const c1 = ctx();
      c1.deployments.deployments["v6.1.0"].equalsAddress = false;
      expect(built(c1).trustTarget.established).to.equal(false);
      const c2 = ctx();
      c2.chain.chains["1"].secondProvider.verifiersSame = false;
      expect(built(c2).trustTarget.established).to.equal(false);
    });

    it("code identity needs the SP1-P1 attribution joins", function () {
      const c = ctx();
      c.sp1p1Gateway.attribution.vkConstantJoin.mismatches = 1;
      expect(built(c).trustTarget.failures).to.include(
        "the verifying-key constants are not joined to the published vk artifact",
      );
    });

    it("code identity needs the same real-proof verdicts from the deployed template on every chain", function () {
      expect(
        built().trustTarget.chainExecution.map((c) => [c.chainId, c.verdictsAsExpected, c.providersAgree]),
      ).to.deep.equal([
        ["1", true, true],
        ["8453", true, true],
        ["11155111", true, true],
        ["84532", true, true],
      ]);
      const c1 = ctx();
      c1.chainExec.chains["8453"].verdicts.v600RealProof = "revert ProofInvalid";
      expect(built(c1).trustTarget.failures).to.include(
        "chain 8453: the verifier template does not give the expected verdicts",
      );
      expect(built(c1).decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
      const c2 = ctx();
      c2.chainExec.chains["84532"].providersAgree = false;
      expect(built(c2).trustTarget.failures).to.include(
        "chain 84532: the providers disagree on the verifier's verdicts",
      );
      const c3 = ctx();
      delete c3.chainExec.chains["11155111"];
      expect(built(c3).trustTarget.failures).to.include("chain 11155111: the verifier template was not executed there");
      // The observation cannot grade itself: the required verdicts are the validator's. A canary that verifies (a
      // missing pairing precompile) fails the chain even where the observation's own expectations were relaxed.
      const c4 = ctx();
      const relaxed = c4.chainExec as unknown as { expected: Record<string, string> };
      relaxed.expected = { v610RealProof: "success" };
      c4.chainExec.chains["84532"].verdicts.v610OddWordCanary = "success";
      expect(built(c4).trustTarget.failures).to.include(
        "chain 84532: the verifier template does not give the expected verdicts",
      );
      expect(REQUIRED_CHAIN_VERDICTS).to.deep.equal({
        v610RealProof: "success",
        v610TamperedPublicValues: "revert ProofInvalid",
        v610OddWordCanary: "revert ProofInvalid",
        v600RealProof: "success",
        v600TamperedPublicValues: "revert ProofInvalid",
      });
    });

    it("the per-chain verdicts count only for the calls this receipt names, rebuilt byte for byte", function () {
      const tt = built().trustTarget;
      expect([tt.chainCallsBound, tt.canaryHasPositiveControl]).to.deep.equal([true, true]);
      const rebuilt = expectedChainCalls(ctx());
      expect(Object.keys(rebuilt)).to.deep.equal(Object.keys(REQUIRED_CHAIN_VERDICTS));
      const unbound = "the per-chain calls are not the real proofs, tampered copies and canary this receipt names";
      const breaks: [string, (c: DecisionContext) => void][] = [
        // Other bytes than the canary this receipt names.
        [
          "canary bytes",
          (c) =>
            (c.chainExec.calls.v610OddWordCanary.data = c.chainExec.calls.v610OddWordCanary.data.slice(0, -1) + "2"),
        ],
        ["another target", (c) => (c.chainExec.calls.v600RealProof.to = c.inputs.trustTargetSelection.verifier)],
        [
          "a missing call",
          (c) => delete (c.chainExec.calls as Partial<typeof c.chainExec.calls>).v610TamperedPublicValues,
        ],
        ["another source transaction", (c) => (c.chainExec.proofSource.transaction = `0x${"ab".repeat(32)}`)],
        [
          "another source observation",
          (c) => (c.chainExec.proofSource.observation = "upstream-proof-fixture.raw.json"),
        ],
        // A different real proof would rebuild different calldata from what was sent.
        [
          "another proof",
          (c) => {
            const pv = c.mainnetProof.call.publicValues;
            c.mainnetProof.call.publicValues = pv.slice(0, -2) + (pv.endsWith("00") ? "01" : "00");
          },
        ],
      ];
      for (const [name, breakIt] of breaks) {
        const c = ctx();
        breakIt(c);
        const r = built(c);
        expect(r.trustTarget.chainCallsBound, name).to.equal(false);
        expect(r.trustTarget.failures, name).to.include(unbound);
        expect(r.decisions.SP1_TRUST_TARGET_DECISION, name).to.equal("UNRESOLVED");
      }
    });

    it("the canary counts only with its positive control: refused by the pinned code, accepted without the pairing precompile", function () {
      for (const fact of [
        "oddWordCanaryRefusedByPinnedCode",
        "oddWordCanaryAcceptedWithoutPairingPrecompile",
      ] as const) {
        const c = ctx();
        c.inputs.probeFacts.semantics[fact] = false;
        const r = built(c);
        expect(r.trustTarget.canaryHasPositiveControl, fact).to.equal(false);
        expect(r.trustTarget.failures, fact).to.include(
          "the odd-word canary has no positive control: it cannot show a missing pairing precompile",
        );
        expect(r.decisions.SP1_TRUST_TARGET_DECISION, fact).to.equal("UNRESOLVED");
      }
    });

    it("the real-proof control speaks for v6.1.0 only while both wrappers share their statements", function () {
      const c = ctx();
      c.fixture.templateComparison.nonConstantLinesSameMultiset = false;
      expect(built(c).trustTarget.failures).to.include(
        "the v6.0.0 and v6.1.0 wrappers no longer share their statements: the chain-execution control does not transfer",
      );
    });

    it("code identity needs the probe suite to have run the mainnet verifier bytes", function () {
      const c = ctx();
      c.inputs.probeFacts.bytes.v610RuntimeEqualsMainnet = false;
      const r = built(c);
      expect(r.trustTarget.failures).to.include("the probe suite did not run the mainnet verifier bytes");
      expect(r.decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
    });

    it("code identity needs the subject's SP1 circuit to be the target version", function () {
      const c = ctx();
      c.sp1p1Receipt.subject.circuitVersion = "v6.0.0";
      const r = built(c);
      expect(r.trustTarget.circuitVersionMatchesSubject).to.equal(false);
      expect(r.trustTarget.established).to.equal(false);
      expect(r.decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
    });

    it("code identity needs an exact (not partial) Sourcify match", function () {
      const c = ctx();
      for (const s of c.sp1p1Gateway.sourcify) if (s.chainId === 1) s.match = "match";
      expect(built(c).trustTarget.failures).to.include("no Sourcify exact match for the verifier on mainnet");
    });

    it("a selector-only pin names the chains where the selector is unrouted", function () {
      const c = ctx();
      const r84532 = c.chain.chains["84532"].gateway.routes.find((x) => x.selector === "0x4388a21c")!;
      r84532.frozen = true;
      const squat = option(built(c), "B0").widen.find((l) => l.lever === "addRoute (route squat)")!;
      expect(squat.chains).to.deep.equal(["84532", "any chain not measured here"]);
      expect(option(built(), "B0").widen.find((l) => l.lever === "addRoute (route squat)")!.chains).to.deep.equal([
        "any chain not measured here",
      ]);
    });

    it("a gateway with a set EIP-1967 slot is reported as code-mutable, also where only its freeze bit is read", function () {
      const mutable = (r: Td1DecisionReceipt) => ["A", "AF", "D"].map((id) => option(r, id).gatewayCodeMutable);
      expect(mutable(built())).to.deep.equal([null, false, false]);
      const c = ctx();
      c.chain.chains["1"].gateway.eip1967ImplementationSlot = `0x${"0".repeat(63)}1`;
      expect(mutable(built(c))).to.deep.equal([null, true, true]);
    });

    it("an option that reads the upstream gateway is reproducible only from the mainnet gateway bytes", function () {
      const reproducible = (r: Td1DecisionReceipt) =>
        ["A", "AF", "B"].map((id) => option(r, id).trustRootIndependentlyReproducible);
      expect(reproducible(built())).to.deep.equal([true, true, true]);
      const c = ctx();
      c.inputs.probeFacts.bytes.gatewayRuntimeEqualsMainnet = false;
      expect(reproducible(built(c))).to.deep.equal([true, false, false]);
    });

    it("the pinned gateway loses viability unless every pin fact holds", function () {
      for (const key of ["otherSelectorRouteRejected", "squattedRouteRejectedAtConstruction"] as const) {
        const c = ctx();
        c.inputs.probeFacts.B_selectorRouteCodePinned[key] = false;
        expect(option(built(c), "B").viable, key).to.equal(false);
      }
    });

    it("an ungated addRoute makes anyone an authorization principal on an unpinned gateway, not on a pinned one", function () {
      const c = ctx();
      c.inputs.probeFacts.D_upstreamGatewayUnpinned.nonOwnerCanAddRoute = true;
      const r = built(c);
      expect(option(r, "D").widen.some((l) => l.principal === "anyone (addRoute not owner-gated)")).to.equal(true);
      expect(option(r, "B0").widen.some((l) => l.principal.startsWith("anyone"))).to.equal(true);
      expect(option(r, "B").viable).to.equal(true);
    });

    it("a verifier with a lever to alter its relation is no trust target, pinned or not", function () {
      const c = ctx();
      c.inputs.probeFacts.A_directCodePinned.noPrincipalCanAlterAcceptedRelation = false;
      const r = built(c);
      expect(option(r, "A").viable).to.equal(false);
      expect(option(r, "B").viable).to.equal(false);
      expect(r.decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
    });

    it("decideTrustTarget ranks external liveness levers before path length, then path length", function () {
      const base = built().options;
      const synthetic = (id: string, disable: number, path: number) => ({
        ...option(built(), "A"),
        id,
        decisionValue: "SELECTOR_PINNED_GATEWAY" as const,
        path: Array(path).fill("hop"),
        disable: Array.from({ length: disable }, (_, i) => ({
          ...base[0].widen[0],
          principal: `p${i}`,
          governed: false,
        })),
      });
      expect(decideTrustTarget([synthetic("short-levered", 1, 2), synthetic("long-clean", 0, 9)]).optionId).to.equal(
        "long-clean",
      );
      expect(decideTrustTarget([synthetic("long", 0, 9), synthetic("short", 0, 2)]).optionId).to.equal("short");
      expect(decideTrustTarget([])).to.deep.equal({ decision: "UNRESOLVED", optionId: null });
    });

    it("an unpinned gateway whose owner is (falsely) recorded as unable to widen is still refused by the rules", function () {
      const c = ctx();
      c.inputs.probeFacts.D_upstreamGatewayUnpinned.ownerAddRouteWidensAcceptedRelation = false;
      const r = built(c);
      expect(option(r, "D").acceptedRelationMutableOutsideTimelock).to.equal(false);
      expectRule(r, "option D: an owner-mutable route registry cannot be classified immutable");
    });

    it("measures the upstream freeze lag: 181 days from the advisory to the v6.0.0 freeze", function () {
      const r = built();
      expect(r.upstreamTimeline.daysFromAdvisoryToFreeze).to.equal(181);
      expect(r.upstreamTimeline.advisedVersionRouteFrozenUtc).to.equal("2026-10-09T06:14:59.000Z");
    });

    it("finds the indexer gap SP1-P1's route history inherited", function () {
      const gap = built().gatewayPosture.routeHistoryIndexerGap!;
      expect(gap.missingFromSp1P1History).to.equal(true);
      expect(gap.indexerHasLog).to.equal(false);
      expect(built().claims.GATEWAY_ROUTE_HISTORY_COMPLETE.status).to.equal("NOT_ESTABLISHED");
    });

    it("exercises the pinned key with a real v6.1.0 proof, and refuses each broken link of that join", function () {
      const real = built().trustTarget.realProofOnPinnedKey;
      expect(real).to.deep.equal({
        transaction: "0x508db9c61a70400710d883241e83b42f9544ba363c5a82959e0db184d5cef3f4",
        programVKey: "0x006cd47fd23937a6d247696cace28c22d2c6a8280447e6ac45a3571de232d6e3",
        verifiedInProbe: true,
        established: true,
      });
      expect(built().claims.PINNED_VERIFYING_KEY_REAL_PROOF.status).to.equal("ESTABLISHED");
      const breaks: [string, (c: DecisionContext) => void][] = [
        ["selector", (c) => (c.mainnetProof.decoded.proofSelector = "0x0e78f4db")],
        ["exit code", (c) => (c.mainnetProof.decoded.exitCode = "1")],
        ["vk root", (c) => (c.mainnetProof.decoded.vkRoot = `0x${"00".repeat(32)}`)],
        ["receipt", (c) => (c.mainnetProof.source.receiptStatus = 0)],
        ["one provider", (c) => (c.mainnetProof.source.transactionOnBothProviders = false)],
        ["probe accept", (c) => (c.inputs.probeFacts.semantics.realV610ProofAcceptedDirect = false)],
        ["probe tamper", (c) => (c.inputs.probeFacts.semantics.realV610TamperedRejectedDirectAndViaGateway = false)],
        // Two roots across chains: the proof's root matching the first one does not identify "the pinned key".
        ["split root", (c) => (c.chain.chains["84532"].verifiers["v6.1.0"].VK_ROOT = `0x${"11".repeat(32)}`)],
      ];
      for (const [name, breakIt] of breaks) {
        const c = ctx();
        breakIt(c);
        const r = built(c);
        expect(r.trustTarget.realProofOnPinnedKey.established, name).to.equal(false);
        expect(r.claims.PINNED_VERIFYING_KEY_REAL_PROOF.status, name).to.equal("NOT_ESTABLISHED");
        expect(r.decisions.SP1_TRUST_TARGET_DECISION, name).to.equal("UNRESOLVED");
      }
    });

    it("a verdict may depend only on the call: extra reads, non-precompile targets or unbounded code are refused", function () {
      expect(built().trustTarget.runtime).to.deep.include({
        reachableEnvironmentReads: { EXTCODESIZE: 1 },
        constantCallTargets: ["0x05", "0x06", "0x07", "0x08"],
        metadataIsSolcCbor: true,
      });
      const c1 = ctx();
      c1.inputs.probeFacts.verifierRuntime.v610ReachableEnvironmentReads = { EXTCODESIZE: 1, SLOAD: 2 };
      expect(built(c1).trustTarget.failures).to.include(
        "the verifier runtime reads SLOAD: its verdict could depend on mutable state",
      );
      const c2 = ctx();
      c2.inputs.probeFacts.verifierRuntime.v610ConstantStaticcallTargets.push("0x01");
      expect(built(c2).trustTarget.failures).to.include(
        "the verifier runtime calls 0x01, which is not a BN254/modexp precompile",
      );
      const c3 = ctx();
      c3.inputs.probeFacts.verifierRuntime.v610MetadataIsSolcCbor = false;
      expect(built(c3).trustTarget.failures).to.include(
        "the runtime's trailing metadata is not solc's CBOR: the scan may miss code",
      );
      for (const c of [c1, c2, c3]) expect(built(c).decisions.SP1_TRUST_TARGET_DECISION).to.equal("UNRESOLVED");
    });

    it("AF: a read-only freeze coupling widens nothing, and its freeze protects only while the route pin holds", function () {
      const af = option(built(), "AF");
      expect(af.viable).to.equal(true);
      expect(af.widen.filter((l) => !l.governed)).to.deep.equal([]);
      expect(af.disable.map((l) => [l.lever, l.protectiveOnVerifierDefect])).to.deep.equal([
        ["freezeRoute", true],
        ["freezeRoute", true],
      ]);
      expect(af.upstreamGovernanceDependency).to.equal("liveness");
      expect(af.defectResponse.length).to.equal(3);
      expect(af.proxyOrAdmin).to.equal("upstream Ownable owner, read for its freeze bit only (no proxy)");
      expect(af.routeRegistry).to.equal(false);
      // The receipt carries each option's components, so the rules can see which options read the upstream gateway.
      expect(built().options.map((o) => [o.id, o.components])).to.deep.equal(
        ctx().inputs.options.map((o) => [o.id, o.components]),
      );
      expect(af.crossChainIdentity).to.contain("; the freeze bit ties each chain to its gateway owner (1: Safe 1.3.0");
      expect(option(built(), "A").crossChainIdentity).to.not.contain("freeze bit");
      const alternatives = (c: DecisionContext) =>
        built(c).decisions.DEFECT_RESPONSE_COUPLING.viableAlternatives.map((a) => a.id);
      for (const pin of ["selector", "routeVerifier", "gatewayCode"]) {
        const c = ctx();
        const input = c.inputs.options.find((o) => o.id === "AF")!;
        input.pins = input.pins.filter((p) => p !== pin);
        expect(
          option(built(c), "AF").disable.every((l) => !l.protectiveOnVerifierDefect),
          pin,
        ).to.equal(true);
        // A freeze that may belong to another verifier's route is a liveness cost only: no defect response.
        expect(option(built(c), "AF").defectResponse, pin).to.deep.equal([PAUSE]);
        expect(alternatives(c), pin).to.deep.equal(["B"]);
      }
      for (const fact of ["squattedRouteRejectedAtConstruction", "otherSelectorRouteGrantsNothing"] as const) {
        const c = ctx();
        c.inputs.probeFacts.AF_directFreezeCoupled[fact] = false;
        expect(alternatives(c), fact).to.deep.equal(["B"]);
      }
      // Without an executed fail-closed freeze, AF has no external lever at all: nothing to trade.
      const c = ctx();
      c.inputs.probeFacts.AF_directFreezeCoupled.upstreamFreezeFailsClosed = false;
      expect(option(built(c), "AF").disable).to.deep.equal([]);
      expect(alternatives(c)).to.deep.equal(["B"]);
    });

    it("records the owner's decision on the defect response, and the trade-off it settled", function () {
      const dc = built().decisions.DEFECT_RESPONSE_COUPLING;
      expect([dc.status, dc.decision, dc.mechanism, dc.decidedBy, dc.decidedOn]).to.deep.equal([
        "DECIDED",
        "WALLETWALL_DETECT_AND_FAIL_CLOSED",
        "LOCAL_ONE_WAY_VERIFIER_HALT",
        "owner",
        "2026-10-15",
      ]);
      expect(dc.haltDesign).to.deep.equal(ctx().inputs.ownerDecisions[0].haltDesign);
      expect(dc.viableAlternatives.map((a) => a.id)).to.deep.equal(["AF", "B"]);
      expect(dc.viableAlternatives[0].externalLivenessPrincipals.length).to.equal(2);
      expect(dc.decidedOptionDefectResponse).to.deep.equal([PAUSE]);
      // AF realizes the freeze coupling; B (same principals, longer path) is dominated and not offered.
      expect(dc.choices.map((x) => [x.id, x.options])).to.deep.equal([
        ["WALLETWALL_DETECT_AND_FAIL_CLOSED", ["A"]],
        ["UPSTREAM_FREEZE_FAIL_CLOSED", ["AF"]],
      ]);
      expect([dc.recommendation, dc.requiredBeforeRealValue]).to.deep.equal([
        "WALLETWALL_DETECT_AND_FAIL_CLOSED",
        true,
      ]);
      const path = built().claims.DEFECT_RESPONSE_PATH.basis;
      expect(path).to.contain("decided by the owner on 2026-10-15");
      expect(path).to.contain(
        "TD2 tests it through every consumer in its scope (PolicyControlBridge, StablecoinVaultSimulator, WalletWallVault); WalletWallMultiSigVault has no recovery path and stays off a haltable wrapper until TD2-MULTISIG-ROTATION",
      );
      // Control: undecided, the same trade-off is an open owner decision and real value waits on it.
      const open = ctx();
      open.inputs.ownerDecisions[0].status = "OWNER_DECISION_REQUIRED";
      const ro = built(open);
      expect([
        ro.decisions.DEFECT_RESPONSE_COUPLING.status,
        ro.decisions.DEFECT_RESPONSE_COUPLING.decision,
        ro.decisions.DEFECT_RESPONSE_COUPLING.haltDesign,
        ro.decisions.DEFECT_RESPONSE_COUPLING.authorityAccounting,
        ro.decisions.DEFECT_RESPONSE_COUPLING.td2Requirements,
        ro.decisions.DEFECT_RESPONSE_MECHANISM,
        ro.decisions.HALT_REVERSIBILITY,
        ro.decisions.RECOVERY,
        ro.decisions.LIVENESS_AUTHORITY_DELTA.classification,
        ro.decisions.AUTHORIZATION_AUTHORITY_DELTA.proposedForTd2,
        ro.decisions.REAL_VALUE_BLOCKER,
        ro.decisions.REAL_VALUE_REQUIREMENTS,
      ]).to.deep.equal([
        "OWNER_DECISION_REQUIRED",
        null,
        null,
        null,
        [],
        "UNDECIDED",
        "UNDECIDED",
        "UNDECIDED",
        "UNDECIDED",
        [],
        "DEFECT_RESPONSE_COUPLING_UNDECIDED",
        [],
      ]);
      // Undecided, no consumer is in a halt's scope, and no amendment is carried.
      expect(ro.decisions.DEFECT_RESPONSE_COUPLING.recoveryByConsumer.map((x) => x.halt)).to.deep.equal([
        "UNSCOPED",
        "UNSCOPED",
        "UNSCOPED",
        "UNSCOPED",
      ]);
      expect(ro.decisions.DEFECT_RESPONSE_COUPLING.amendments).to.deep.equal([]);
      expect(ro.claims.DEFECT_RESPONSE_PATH.basis).to.contain("open owner decision DEFECT_RESPONSE_COUPLING");
      expect(rulesOf(ro)).to.deep.equal([]);
      // Undecided with no fail-closed alternative left (AF gone, B's route replaceable): the decision does not apply.
      const c1 = ctx();
      c1.inputs.ownerDecisions[0].status = "OWNER_DECISION_REQUIRED";
      c1.inputs.options = c1.inputs.options.filter((o) => o.id !== "AF");
      c1.inputs.probeFacts.B_selectorRouteCodePinned.pinnedRouteReplaceable = true;
      const r1 = built(c1);
      expect(r1.decisions.DEFECT_RESPONSE_COUPLING.status).to.equal("NOT_APPLICABLE");
      expect(r1.claims.DEFECT_RESPONSE_PATH.basis).to.contain("no protective alternative exists");
      expect(rulesOf(r1)).to.deep.equal([]);
      // The decided option is never its own alternative, and a decision made for A is not carried over to B.
      const c2 = ctx();
      c2.inputs.options = c2.inputs.options.filter((o) => o.id === "B");
      const r2 = built(c2);
      expect(r2.decisions.SP1_TRUST_TARGET_OPTION).to.equal("B");
      expect(r2.decisions.DEFECT_RESPONSE_COUPLING.viableAlternatives).to.deep.equal([]);
      expectRule(r2, "the owner's decision must be realized by the decided trust target");
      // B routes through the gateway: its owners' freeze is in the decided path, so they would be a WalletWall authority.
      expect(r2.decisions.UPSTREAM_GATEWAY_OWNER).to.equal("WALLETWALL_AUTHORITY");
      // A missing owner-decision record leaves nothing to choose from, and the rules refuse it.
      const c3 = ctx();
      c3.inputs.ownerDecisions = [];
      const r3 = built(c3).decisions.DEFECT_RESPONSE_COUPLING;
      expect([r3.status, r3.choices, r3.recommendation, r3.rationale, r3.requiredBeforeRealValue]).to.deep.equal([
        "OWNER_DECISION_REQUIRED",
        [],
        null,
        null,
        true,
      ]);
      expectRule(built(c3), "the owner decision offers no choice realized by option A");
      expectRule(built(c3), "the owner decision's recommendation is not one of its choices");
    });

    it("an unresolved trust target has no decided defect response", function () {
      const c = ctx();
      c.inputs.probeFacts.verifierRuntime.v610ForbiddenOpcodes = ["SSTORE"];
      const dc = built(c).decisions.DEFECT_RESPONSE_COUPLING;
      expect([dc.status, dc.decidedOptionDefectResponse, dc.viableAlternatives, dc.haltDesign]).to.deep.equal([
        "NOT_APPLICABLE",
        [],
        [],
        null,
      ]);
    });

    it("derives the authority classification and the halt's outputs from the decided design", function () {
      const halt = (c: DecisionContext) => c.inputs.ownerDecisions[0].haltDesign!;
      const d = built().decisions;
      expect(
        d.LIVENESS_AUTHORITY_DELTA.added.map((l) => [l.lever, l.scope, l.governed, l.protectiveOnVerifierDefect]),
      ).to.deep.equal([["verifierHalt", "liveness", true, true]]);
      expect(d.LIVENESS_AUTHORITY_DELTA.removedVersusBaseline).to.deep.equal(
        d.LIVENESS_DEPENDENCY.removedVersusBaseline,
      );
      expect(d.DEFECT_RESPONSE_COUPLING.measuredConsumers).to.deep.equal([
        "PolicyControlBridge",
        "StablecoinVaultSimulator",
        "WalletWallMultiSigVault",
        "WalletWallVault",
      ]);
      expect(d.DEFECT_RESPONSE_COUPLING.consumersWithoutRecoveryPath).to.deep.equal(["WalletWallMultiSigVault"]);
      expect(d.RECOVERY).to.equal("NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE");
      // If the scan ever showed the multisig vault a rotation (TD1-N11), the derivation would follow the code: no
      // consumer stranded, and recovery claimed for every consumer once the halt applies to it too. The rules refuse
      // both, because TD2-MULTISIG-ROTATION is unbuilt: a scanned rotation is not the gate's (delay, target gating,
      // proofs), and the design no longer describes the code.
      const rot = ctx();
      rot.inputs.probeFacts.verifierConsumers.consumersWithTimelockedRotation.push("WalletWallMultiSigVault");
      rot.inputs.probeFacts.verifierConsumers.rotationDelaySeconds.WalletWallMultiSigVault = 172_800;
      expect(built(rot).decisions.DEFECT_RESPONSE_COUPLING.consumersWithoutRecoveryPath).to.deep.equal([]);
      expect(built(rot).decisions.RECOVERY).to.equal("NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE");
      expectRule(built(rot), "WalletWallMultiSigVault can recover, so it cannot be left outside the halt");
      expectRule(
        built(rot),
        "WalletWallMultiSigVault shows a recovery route before TD2-MULTISIG-ROTATION is built: the design no longer describes the code",
      );
      halt(rot).haltScope = {
        applies: ["PolicyControlBridge", "StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"],
        excludedUntilRecoverable: [],
      };
      expect(built(rot).decisions.RECOVERY).to.equal("NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION");
      for (const e of [
        "WalletWallMultiSigVault may not be in the halt's scope before TD2-MULTISIG-ROTATION is built",
        "WalletWallMultiSigVault waits outside the halt for TD2-MULTISIG-ROTATION",
        "WalletWallMultiSigVault shows a recovery route before TD2-MULTISIG-ROTATION is built: the design no longer describes the code",
      ])
        expectRule(built(rot), e);
      // A scope as wide as the measured consumers narrows nothing, so it needs no amendment on record.
      delete rot.inputs.ownerDecisions[0].amendments;
      expect(rulesOf(built(rot)).filter((e) => e.includes("the owner's amendment, on record"))).to.deep.equal([]);
      // A delay constant alone is not a rotation: only an owner-gated rotation carries its delay.
      const constantOnly = ctx();
      constantOnly.inputs.probeFacts.verifierConsumers.rotationDelaySeconds.WalletWallMultiSigVault = 172_800;
      expect(
        built(constantOnly).decisions.DEFECT_RESPONSE_COUPLING.recoveryByConsumer.find(
          (x) => x.consumer === "WalletWallMultiSigVault",
        )!.rotationDelaySeconds,
      ).to.equal(null);
      // Applying the halt to every consumer does not make one that cannot rotate recoverable; and a scan that finds no
      // consumer is no evidence that every consumer recovers.
      const stuck = ctx();
      halt(stuck).haltScope = {
        applies: ["PolicyControlBridge", "StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"],
        excludedUntilRecoverable: [],
      };
      expect(built(stuck).decisions.RECOVERY).to.equal("NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE");
      const noneFound = ctx();
      noneFound.inputs.probeFacts.verifierConsumers.pqVerifierConsumers = [];
      expect(built(noneFound).decisions.RECOVERY).to.equal("NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE");
      // The bridge recovers through the consumers it follows: drop that, or let it follow one that cannot rotate (or
      // none at all), and it is stranded too.
      const stranded = (c: DecisionContext) => built(c).decisions.DEFECT_RESPONSE_COUPLING.consumersWithoutRecoveryPath;
      const fol = ctx();
      fol.inputs.probeFacts.verifierConsumers.consumersFollowingTheirConsumer = [];
      expect(stranded(fol)).to.deep.equal(["PolicyControlBridge", "WalletWallMultiSigVault"]);
      const src = ctx();
      src.inputs.probeFacts.verifierConsumers.bridgeCredentialSources.push("WalletWallMultiSigVault");
      expect(stranded(src)).to.deep.equal(["PolicyControlBridge", "WalletWallMultiSigVault"]);
      const none = ctx();
      none.inputs.probeFacts.verifierConsumers.bridgeCredentialSources = [];
      expect(stranded(none)).to.deep.equal(["PolicyControlBridge", "WalletWallMultiSigVault"]);
      // A widening capability beyond the retained vault rotation is recorded by what it holds, whatever its own flags
      // or status say (the rules then refuse anything but a TD2 proposal); a capability that cannot widen is not.
      const acct = (c: DecisionContext) => c.inputs.ownerDecisions[0].authorityAccounting!;
      const proposed = (c: DecisionContext) => built(c).decisions.AUTHORIZATION_AUTHORITY_DELTA.proposedForTd2;
      const flags = ctx();
      acct(flags).proposedMultisigRotation.widensAuthorization = false;
      acct(flags).proposedMultisigRotation.scope = "liveness";
      expect(proposed(flags).map((p) => p.capabilities)).to.deep.equal([["PQ_VERIFIER_ROTATION"]]);
      const pause = ctx();
      acct(pause).proposedMultisigRotation.capabilities = ["pause"];
      expect(proposed(pause)).to.deep.equal([]);
      const decidedNow = ctx();
      acct(decidedNow).proposedMultisigRotation.status = "DECIDED";
      expect(proposed(decidedNow).map((p) => p.status)).to.deep.equal(["DECIDED"]);
      expectRule(built(decidedNow), "the multisig rotation is proposed for TD2, not part of the decided design");
      const unstated = ctx();
      delete acct(unstated).proposedMultisigRotation.status;
      expect(proposed(unstated).map((p) => p.status)).to.deep.equal(["UNSTATED"]);
      // The vault owner's rotation is the retained baseline (AUTHORIZATION_AUTHORITY_DELTA.retained), not a proposal.
      expect(proposed(ctx()).map((p) => p.principal)).to.deep.equal(["WALLETWALL_MULTISIG_VAULT_OWNER"]);
      const unclassified = ctx();
      delete acct(unclassified).proposedMultisigRotation.classification;
      expect(proposed(unclassified).map((p) => p.classification)).to.deep.equal(["UNCLASSIFIED"]);
      // A rotation is a widening power: a halt principal holding one is authority.
      const rotHalt = ctx();
      halt(rotHalt).haltPrincipal.powers.push("PQ_VERIFIER_ROTATION");
      expect(built(rotHalt).decisions.AUTHORIZATION_AUTHORITY_DELTA.classification).to.equal(
        "NEW_AUTHORIZATION_PRINCIPAL",
      );
      // An unhalt transition makes the halt reversible.
      const c1 = ctx();
      halt(c1).transitions.push({ from: "HALTED", to: "ACTIVE", trigger: "HALT_PRINCIPAL_CALL" });
      expect(built(c1).decisions.HALT_REVERSIBILITY).to.equal("REVERSIBLE");
      // A widening power is authority, whatever the principal is called; any extra power is more than a halt.
      const c2 = ctx();
      halt(c2).haltPrincipal.powers.push("WIDEN_ACCEPTED_RELATION");
      expect([
        built(c2).decisions.AUTHORIZATION_AUTHORITY_DELTA.classification,
        built(c2).decisions.LIVENESS_AUTHORITY_DELTA.classification,
      ]).to.deep.equal(["NEW_AUTHORIZATION_PRINCIPAL", "WALLETWALL_EMERGENCY_PRINCIPAL_WITH_MORE_THAN_HALT"]);
      const c3 = ctx();
      halt(c3).haltPrincipal.powers.push("UNHALT");
      expect([
        built(c3).decisions.AUTHORIZATION_AUTHORITY_DELTA.classification,
        built(c3).decisions.LIVENESS_AUTHORITY_DELTA.classification,
      ]).to.deep.equal(["NO_NEW_AUTHORIZATION_PRINCIPAL", "WALLETWALL_EMERGENCY_PRINCIPAL_WITH_MORE_THAN_HALT"]);
      // An upstream signal that moves the halt makes the upstream gateway owner a WalletWall authority again.
      const c4 = ctx();
      halt(c4).transitions[0].trigger = "RouteFrozen";
      expect(built(c4).decisions.UPSTREAM_GATEWAY_OWNER).to.equal("WALLETWALL_AUTHORITY");
      const c5 = ctx();
      halt(c5).detectionSignalsControlState = true;
      expect(built(c5).decisions.UPSTREAM_GATEWAY_OWNER).to.equal("WALLETWALL_AUTHORITY");
      // Recovery is whatever the design says, and the rules hold it to the decided path.
      const c6 = ctx();
      halt(c6).recovery = "UNHALT_IN_PLACE";
      expect(built(c6).decisions.RECOVERY).to.equal("UNHALT_IN_PLACE");
      // The output then says what the design says; the design rule, not the output rule, refuses it.
      expect(rulesOf(built(c6)).filter((e) => e.startsWith("RECOVERY must be"))).to.deep.equal([]);
      expectRule(built(c6), "recovery from HALTED is a new wrapper and the timelocked rotation, nothing else");
    });

    it("refuses each violation the owner named, built from the inputs", function () {
      const halt = (c: DecisionContext) => c.inputs.ownerDecisions[0].haltDesign!;
      const violations: [string, (c: DecisionContext) => void, string[]][] = [
        [
          "the halt principal can unhalt",
          (c) => halt(c).haltPrincipal.powers.push("UNHALT"),
          ["the halt principal may only halt (also holds: UNHALT)"],
        ],
        [
          "an in-place HALTED -> ACTIVE transition",
          (c) => halt(c).transitions.push({ from: "HALTED", to: "ACTIVE", trigger: "HALT_PRINCIPAL_CALL" }),
          ["the halt has one transition, ACTIVE -> HALTED: nothing leaves HALTED in place"],
        ],
        [
          "the verifier changes while halted",
          (c) => (halt(c).wrapperIdentity.sp1Verifier = "MUTABLE_WHILE_HALTED"),
          ["the wrapper's SP1 verifier is immutable, halted or not"],
        ],
        [
          "the halt principal can select another verifier",
          (c) => halt(c).haltPrincipal.powers.push("CHANGE_SP1_VERIFIER"),
          ["the halt principal may only halt (also holds: CHANGE_SP1_VERIFIER)"],
        ],
        [
          "PROGRAM_VKEY changes",
          (c) => (halt(c).wrapperIdentity.programVKey = "MUTABLE"),
          ["the wrapper's PROGRAM_VKEY is immutable, halted or not"],
        ],
        [
          "RouteFrozen moves the halt automatically",
          (c) => (halt(c).transitions[0].trigger = "RouteFrozen"),
          [
            "only the halt principal's call moves the halt; detection signals are evidence",
            "the upstream gateway owner is not a WalletWall authority under the decided response",
          ],
        ],
        [
          "detection signals control the state",
          (c) => (halt(c).detectionSignalsControlState = true),
          [
            "detection signals cannot control the halt",
            "the upstream gateway owner is not a WalletWall authority under the decided response",
          ],
        ],
        [
          "PolicyControlBridge bypasses the halt (left out of its scope)",
          (c) => (halt(c).haltScope.applies = halt(c).haltScope.applies.filter((x) => x !== "PolicyControlBridge")),
          ["the halt's scope must name every consumer of the verifier (missing: PolicyControlBridge)"],
        ],
        [
          "PolicyControlBridge bypasses the halt (excluded as if it could not recover)",
          (c) => {
            halt(c).haltScope.applies = halt(c).haltScope.applies.filter((x) => x !== "PolicyControlBridge");
            halt(c).haltScope.excludedUntilRecoverable.push({
              consumer: "PolicyControlBridge",
              gate: "TD2-MULTISIG-ROTATION",
              interim: "NOT_BOUND_TO_THE_SP1_PATH",
              authorizedBy: "TD1-N11-PREREQUISITE",
            });
          },
          [
            "PolicyControlBridge can recover, so it cannot be left outside the halt",
            "PolicyControlBridge waits for TD2-MULTISIG-ROTATION, which is not its own gate",
            "TD2-COMMON-VERIFIER-HALT: it must refuse a haltable wrapper to every consumer kept outside the halt",
          ],
        ],
        [
          "a halt at a consumer, not at the wrapper",
          (c) => (halt(c).location = "VAULT_PAUSE"),
          ["the halt sits at the verifier wrapper, which the consumers in its scope verify through"],
        ],
        [
          "an authorization-neutral principal with widening power",
          (c) => halt(c).haltPrincipal.powers.push("WIDEN_ACCEPTED_RELATION"),
          ["the halt principal may only halt (also holds: WIDEN_ACCEPTED_RELATION)"],
        ],
        [
          "recovery without a new wrapper and the timelocked rotation",
          (c) => (halt(c).recovery = "UNHALT_IN_PLACE"),
          ["recovery from HALTED is a new wrapper and the timelocked rotation, nothing else"],
        ],
        [
          "a halt principal without the halt",
          (c) => (halt(c).haltPrincipal.powers = []),
          ["the halt principal may only halt (also holds: nothing, and no HALT)"],
        ],
        [
          "a decision for AF",
          (c) => (c.inputs.ownerDecisions[0].decision = "UPSTREAM_FREEZE_FAIL_CLOSED"),
          [
            "the owner decided WALLETWALL_DETECT_AND_FAIL_CLOSED; AF is not chosen",
            "the owner's decision must be realized by the decided trust target",
          ],
        ],
        [
          "another mechanism",
          (c) => (c.inputs.ownerDecisions[0].mechanism = "UPSTREAM_ROUTE_FREEZE"),
          ["the decided mechanism is LOCAL_ONE_WAY_VERIFIER_HALT"],
        ],
        [
          "a decision outside the choices",
          (c) => (c.inputs.ownerDecisions[0].decision = "SOMETHING_ELSE"),
          ["the owner's decision is not one of the offered choices"],
        ],
        [
          "no halt design",
          (c) => delete c.inputs.ownerDecisions[0].haltDesign,
          ["a decided defect response needs its halt design"],
        ],
      ];
      for (const [name, violate, expected] of violations) {
        const c = ctx();
        violate(c);
        const errors = rulesOf(built(c));
        for (const e of expected) expect(errors, name).to.include(e);
      }
    });

    it("refuses each violation of the owner's amendment (TD1-N11), built from the inputs", function () {
      const od = (c: DecisionContext) => c.inputs.ownerDecisions[0];
      const scope = (c: DecisionContext) => od(c).haltDesign!.haltScope;
      const acct = (c: DecisionContext) => od(c).authorityAccounting!;
      const req = (c: DecisionContext, id: string) => od(c).td2Requirements!.find((r) => r.id === id)!;
      const gate = (c: DecisionContext) => req(c, "TD2-MULTISIG-ROTATION");
      const MSV = "WalletWallMultiSigVault";
      const violations: [string, (c: DecisionContext) => void, string[]][] = [
        [
          "the halt applied to the multisig vault before it can rotate",
          (c) => {
            scope(c).excludedUntilRecoverable = [];
            scope(c).applies.push(MSV);
          },
          [
            `the halt may not be applied to ${MSV}: it cannot leave a halted wrapper`,
            `${MSV} may not be in the halt's scope before TD2-MULTISIG-ROTATION is built`,
            `${MSV} waits outside the halt for TD2-MULTISIG-ROTATION`,
          ],
        ],
        [
          "the multisig vault dropped from the scope",
          (c) => (scope(c).excludedUntilRecoverable = []),
          [`the halt's scope must name every consumer of the verifier (missing: ${MSV})`],
        ],
        [
          "a consumer named twice",
          (c) => scope(c).applies.push(MSV),
          ["the halt's scope names each measured consumer once, and only those"],
        ],
        [
          "a consumer the scan did not find",
          (c) => scope(c).applies.push("SomeOtherVault"),
          [
            "the halt's scope names each measured consumer once, and only those",
            // Nothing shows it can recover, so the halt may not be applied to it either.
            "the halt may not be applied to SomeOtherVault: it cannot leave a halted wrapper",
          ],
        ],
        [
          "excluded until a gate that is not a frozen requirement",
          (c) => (scope(c).excludedUntilRecoverable[0].gate = "TD3-SOMETHING"),
          [
            `${MSV} waits for TD3-SOMETHING, which is not a frozen TD2 requirement`,
            // Its own gate still names it: it must wait under that one.
            `${MSV} waits outside the halt for TD2-MULTISIG-ROTATION`,
          ],
        ],
        [
          "TD2-MULTISIG-ROTATION dropped",
          (c) => (od(c).td2Requirements = od(c).td2Requirements!.filter((r) => r.id !== "TD2-MULTISIG-ROTATION")),
          [
            `${MSV} waits for TD2-MULTISIG-ROTATION, which is not a frozen TD2 requirement`,
            `TD2-MULTISIG-ROTATION is ${MSV}'s frozen gate`,
          ],
        ],
        [
          "the multisig gate moved onto the common halt (one requirement for both)",
          (c) => {
            const common = req(c, "TD2-COMMON-VERIFIER-HALT");
            Object.assign(common, {
              consumer: MSV,
              invariants: gate(c).invariants,
              stopCondition: gate(c).stopCondition,
            });
            common.executableProofs = [...common.executableProofs!, ...gate(c).executableProofs!];
            od(c).td2Requirements = od(c).td2Requirements!.filter((r) => r.id !== "TD2-MULTISIG-ROTATION");
            scope(c).excludedUntilRecoverable[0].gate = "TD2-COMMON-VERIFIER-HALT";
          },
          [`TD2-MULTISIG-ROTATION is ${MSV}'s frozen gate`],
        ],
        [
          "the multisig vault waits under another consumer's gate",
          (c) => (gate(c).consumer = "PolicyControlBridge"),
          [
            `${MSV} waits for TD2-MULTISIG-ROTATION, which is not its own gate`,
            `TD2-MULTISIG-ROTATION is ${MSV}'s frozen gate`,
            "PolicyControlBridge waits outside the halt for TD2-MULTISIG-ROTATION",
            "PolicyControlBridge may not be in the halt's scope before TD2-MULTISIG-ROTATION is built",
            "PolicyControlBridge shows a recovery route before TD2-MULTISIG-ROTATION is built: the design no longer describes the code",
          ],
        ],
        [
          "an interim other than no SP1 binding",
          (c) => (scope(c).excludedUntilRecoverable[0].interim = "NON_HALTABLE_PINNED_WRAPPER"),
          [
            `until TD2-MULTISIG-ROTATION, ${MSV} is bound to no part of the SP1 path (any other interim is an owner decision)`,
          ],
        ],
        [
          "the multisig vault shows a rotation before its gate is built",
          (c) => {
            c.inputs.probeFacts.verifierConsumers.consumersWithTimelockedRotation.push(MSV);
            c.inputs.probeFacts.verifierConsumers.rotationDelaySeconds[MSV] = 172_800;
          },
          [
            `${MSV} shows a recovery route before TD2-MULTISIG-ROTATION is built: the design no longer describes the code`,
            `${MSV} can recover, so it cannot be left outside the halt`,
          ],
        ],
        [
          "the common halt does not enforce the exclusion",
          (c) => (req(c, "TD2-COMMON-VERIFIER-HALT").excludedConsumersRefusedAHaltableWrapper = []),
          ["TD2-COMMON-VERIFIER-HALT: it must refuse a haltable wrapper to every consumer kept outside the halt"],
        ],
        [
          "the common halt without the exclusion's proof",
          (c) =>
            (req(c, "TD2-COMMON-VERIFIER-HALT").executableProofs = req(
              c,
              "TD2-COMMON-VERIFIER-HALT",
            ).executableProofs!.filter((p) => p !== "EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER")),
          ["TD2-COMMON-VERIFIER-HALT: it must prove EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER"],
        ],
        [
          "recovery to a fresh deployment of the halted identity",
          (c) => (od(c).haltDesign!.recoveryIdentity = "ANY_DESIGNATED_WRAPPER"),
          ["recovery is to an independently established identity, never a fresh deployment of the halted one"],
        ],
        [
          "the narrowed scope without the owner's amendment on record",
          (c) => delete od(c).amendments,
          [`${MSV} is kept outside the halt only by the owner's amendment, on record (TD1-N11-PREREQUISITE)`],
        ],
        [
          // Another owner amendment on record (the review additions kept) does not cover the narrowing.
          "the narrowing attributed to the lane",
          (c) => (od(c).amendments![0].by = "lane"),
          [`${MSV} is kept outside the halt only by the owner's amendment, on record (TD1-N11-PREREQUISITE)`],
        ],
        [
          "an exclusion that cites no amendment",
          (c) => delete (scope(c).excludedUntilRecoverable[0] as { authorizedBy?: string }).authorizedBy,
          [`${MSV} is kept outside the halt only by the owner's amendment, on record (undefined)`],
        ],
        [
          "an exclusion that cites an amendment not on record",
          (c) => (scope(c).excludedUntilRecoverable[0].authorizedBy = "TD1-SOMETHING-ELSE"),
          [`${MSV} is kept outside the halt only by the owner's amendment, on record (TD1-SOMETHING-ELSE)`],
        ],
        [
          "a rotating consumer whose rotation waits less than the repository's",
          (c) => (c.inputs.probeFacts.verifierConsumers.rotationDelaySeconds.StablecoinVaultSimulator = 3600),
          ["StablecoinVaultSimulator: its rotation must wait at least the repository's 172800s (measured: 3600)"],
        ],
        [
          "a rotating consumer whose delay was not measured",
          (c) => delete c.inputs.probeFacts.verifierConsumers.rotationDelaySeconds.WalletWallVault,
          ["WalletWallVault: its rotation must wait at least the repository's 172800s (measured: null)"],
        ],
        [
          "a requirement marked built",
          (c) => (gate(c).status = "BUILT"),
          [
            "TD2-MULTISIG-ROTATION: TD1 freezes requirements and builds none (BUILT)",
            `${MSV} waits for TD2-MULTISIG-ROTATION, which is not a frozen TD2 requirement`,
          ],
        ],
        [
          "the common halt not frozen",
          (c) => (od(c).td2Requirements = od(c).td2Requirements!.filter((r) => r.id !== "TD2-COMMON-VERIFIER-HALT")),
          ["TD2-COMMON-VERIFIER-HALT is frozen for TD2"],
        ],
        [
          "a delay shorter than the repository's",
          (c) => (gate(c).invariants!.minimumDelaySeconds = 172_799),
          ["TD2-MULTISIG-ROTATION: the rotation waits at least the repository's 172800s"],
        ],
        [
          "no delay invariants at all",
          (c) => delete gate(c).invariants,
          [
            "TD2-MULTISIG-ROTATION: the rotation waits at least the repository's 172800s",
            "TD2-MULTISIG-ROTATION: no instantaneous verifier replacement",
            "TD2-MULTISIG-ROTATION: no halt principal may invoke the rotation",
            "TD2-MULTISIG-ROTATION: the rotation targets only a wrapper that passed the SP1 evidence gates",
            "TD2-MULTISIG-ROTATION: no HALTED -> ACTIVE on the old wrapper",
          ],
        ],
        [
          "an instantaneous replacement",
          (c) => (gate(c).invariants!.instantReplacement = true),
          ["TD2-MULTISIG-ROTATION: no instantaneous verifier replacement"],
        ],
        [
          "the halt principal invokes the rotation",
          (c) => (gate(c).invariants!.invokableByHaltPrincipal = true),
          ["TD2-MULTISIG-ROTATION: no halt principal may invoke the rotation"],
        ],
        [
          "a rotation to a wrapper outside the evidence gates",
          (c) => (gate(c).invariants!.targetMustPassEvidenceGates = false),
          ["TD2-MULTISIG-ROTATION: the rotation targets only a wrapper that passed the SP1 evidence gates"],
        ],
        [
          "the old wrapper unhalted",
          (c) => (gate(c).invariants!.oldWrapperUnhalt = true),
          ["TD2-MULTISIG-ROTATION: no HALTED -> ACTIVE on the old wrapper"],
        ],
        [
          "no proof that a malicious replacement is blocked",
          (c) =>
            (gate(c).executableProofs = gate(c).executableProofs!.filter(
              (p) => p !== "MALICIOUS_REPLACEMENT_BLOCKED_OUTSIDE_DELAYED_PATH",
            )),
          ["TD2-MULTISIG-ROTATION: it must prove MALICIOUS_REPLACEMENT_BLOCKED_OUTSIDE_DELAYED_PATH"],
        ],
        [
          "no proof that the halted identity is refused as a target",
          (c) =>
            (gate(c).executableProofs = gate(c).executableProofs!.filter(
              (p) => p !== "HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET",
            )),
          ["TD2-MULTISIG-ROTATION: it must prove HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET"],
        ],
        [
          "no proofs at all",
          (c) => delete gate(c).executableProofs,
          [
            "TD2-MULTISIG-ROTATION: it must prove HALTED_THEN_ROTATED_WITHDRAWAL_SUCCEEDS and MALICIOUS_REPLACEMENT_BLOCKED_OUTSIDE_DELAYED_PATH and HALT_PRINCIPAL_CANNOT_ROTATE_EVEN_AFTER_AN_OWNERSHIP_TRANSFER and HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET",
          ],
        ],
        [
          "no stop condition",
          (c) => delete gate(c).stopCondition,
          ["TD2-MULTISIG-ROTATION: it stops and returns to design rather than weakening the one-way halt"],
        ],
        [
          "a stop condition that weakens the halt instead",
          (c) => (gate(c).stopCondition!.never = "NOTHING"),
          ["TD2-MULTISIG-ROTATION: it stops and returns to design rather than weakening the one-way halt"],
        ],
        [
          "a stop condition that does not stop",
          (c) => (gate(c).stopCondition!.then = "CONTINUE_TO_BUILD"),
          ["TD2-MULTISIG-ROTATION: it stops and returns to design rather than weakening the one-way halt"],
        ],
        [
          "a stop condition that never fires",
          (c) => (gate(c).stopCondition!.when = "NEVER"),
          ["TD2-MULTISIG-ROTATION: it stops and returns to design rather than weakening the one-way halt"],
        ],
        [
          "the rotation labelled authority-neutral",
          (c) => (acct(c).proposedMultisigRotation.classification = "AUTHORITY_NEUTRAL"),
          ["a rotation for an existing principal is a new authorization capability, never authority-neutral"],
        ],
        [
          "the rotation recorded as liveness",
          (c) => {
            acct(c).proposedMultisigRotation.scope = "liveness";
            acct(c).proposedMultisigRotation.widensAuthorization = false;
          },
          ["proposedMultisigRotation: a capability that can widen what verifies is authorization"],
        ],
        [
          "the rotation's widening flag cleared",
          (c) => (acct(c).proposedMultisigRotation.widensAuthorization = false),
          ["proposedMultisigRotation: a capability that can widen what verifies is authorization"],
        ],
        [
          "the rotation's scope set to liveness",
          (c) => (acct(c).proposedMultisigRotation.scope = "liveness"),
          ["proposedMultisigRotation: a capability that can widen what verifies is authorization"],
        ],
        [
          "the rotation held by the halt principal",
          (c) => (acct(c).proposedMultisigRotation.principal = "WALLETWALL_EMERGENCY_HALT_PRINCIPAL"),
          [
            "the rotation is proposed for the multisig vault's existing owner",
            "the halt principal is never a vault owner, and never holds a rotation",
          ],
        ],
        [
          "the multisig vault's owner as the halt principal",
          (c) => {
            od(c).haltDesign!.haltPrincipal.id = "WALLETWALL_MULTISIG_VAULT_OWNER";
            acct(c).haltPrincipal.principal = "WALLETWALL_MULTISIG_VAULT_OWNER";
          },
          ["the halt principal is never a vault owner, and never holds a rotation"],
        ],
        [
          "the multisig vault's owner recorded under the halt principal's name",
          (c) => (acct(c).multisigOwnerToday.principal = "WALLETWALL_EMERGENCY_HALT_PRINCIPAL"),
          ["the halt principal is never a vault owner, and never holds a rotation"],
        ],
        [
          "the halt principal accounted with a rotation",
          (c) => acct(c).haltPrincipal.capabilities.push("PQ_VERIFIER_ROTATION"),
          [
            "haltPrincipal: a capability that can widen what verifies is authorization",
            "the halt principal is accounted with the halt design's principal and powers",
          ],
        ],
        [
          "the halt principal accounted under another name",
          (c) => (acct(c).haltPrincipal.principal = "SOMEONE_ELSE"),
          ["the halt principal is accounted with the halt design's principal and powers"],
        ],
        [
          "the multisig vault's owner accounted beyond its code",
          (c) => acct(c).multisigOwnerToday.capabilities.push("setPqVerifier"),
          [
            "the multisig vault's owner is accounted with the onlyOwner functions its code declares",
            "the multisig vault's owner holds more than pause and unpause (setPqVerifier)",
          ],
        ],
        [
          "the multisig vault's code gains an owner function",
          (c) => c.inputs.probeFacts.verifierConsumers.multisigOwnerOnlyFunctions.push("setPqVerifier"),
          ["the multisig vault's owner is accounted with the onlyOwner functions its code declares"],
        ],
        [
          "the rotation is something else",
          (c) => {
            acct(c).proposedMultisigRotation.capabilities = ["PAUSE_ALL"];
            acct(c).proposedMultisigRotation.scope = "liveness";
            acct(c).proposedMultisigRotation.widensAuthorization = false;
          },
          ["the proposed capability is the multisig vault's pqVerifier rotation, and nothing else"],
        ],
        [
          "the rotation carries a further power",
          (c) => acct(c).proposedMultisigRotation.capabilities.push("BYPASS_VERIFICATION"),
          ["the proposed capability is the multisig vault's pqVerifier rotation, and nothing else"],
        ],
        [
          "an extra accounting row (a widening capability adopted outside the proposal)",
          (c) =>
            Object.assign(acct(c), {
              adopted: {
                principal: "WALLETWALL_MULTISIG_VAULT_OWNER",
                capabilities: ["PQ_VERIFIER_ROTATION"],
                scope: "authorization",
                widensAuthorization: true,
                status: "DECIDED",
                classification: "AUTHORITY_NEUTRAL",
              },
            }),
          [
            "the authority accounting holds exactly haltPrincipal, vaultOwnerToday, multisigOwnerToday, proposedMultisigRotation",
          ],
        ],
        [
          "the vault owner accounted without its rotation",
          (c) => (acct(c).vaultOwnerToday.capabilities = ["pause", "unpause"]),
          [
            "the vault owner is accounted with the retained rotation and its pause, nothing more",
            "vaultOwnerToday: a capability that cannot widen what verifies is liveness",
          ],
        ],
        [
          "the vault owner's rotation recorded as something other than retained",
          (c) => (acct(c).vaultOwnerToday.status = "PROPOSED_FOR_TD2"),
          ["the vault owner is accounted with the retained rotation and its pause, nothing more"],
        ],
        [
          "the halt principal is the vault owner who holds the in-scope rotation",
          (c) => {
            od(c).haltDesign!.haltPrincipal.id = "WALLETWALL_VAULT_OWNER";
            acct(c).haltPrincipal.principal = "WALLETWALL_VAULT_OWNER";
          },
          ["the halt principal is never a vault owner, and never holds a rotation"],
        ],
        [
          "the rotation folded into the decided design",
          (c) => (acct(c).proposedMultisigRotation.status = "DECIDED"),
          ["the multisig rotation is proposed for TD2, not part of the decided design"],
        ],
        [
          "the rotation without its own review",
          (c) => (acct(c).proposedMultisigRotation.requires = []),
          [
            "the proposed rotation requires separate authority accounting",
            "the proposed rotation requires executable review",
          ],
        ],
        [
          "no authority accounting",
          (c) => delete od(c).authorityAccounting,
          ["the decided halt needs its authority accounting"],
        ],
        [
          "the bridge could follow the multisig vault",
          (c) => c.inputs.probeFacts.verifierConsumers.bridgeCredentialSources.push(MSV),
          ["the halt may not be applied to PolicyControlBridge: it cannot leave a halted wrapper"],
        ],
      ];
      for (const [name, violate, expected] of violations) {
        const c = ctx();
        violate(c);
        const errors = rulesOf(built(c));
        for (const e of expected) expect(errors, name).to.include(e);
      }
      // Control: the amendment as recorded passes every rule.
      expect(rulesOf(built())).to.deep.equal([]);
    });

    it("the upgrade and cross-chain models follow the decided option and the per-chain evidence", function () {
      const models = (r: Td1DecisionReceipt) => [r.decisions.UPGRADE_MODEL, r.decisions.CROSS_CHAIN_MODEL];
      expect(models(built())).to.deep.equal([
        "EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION",
        "CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK",
      ]);
      // A decided route registry is a per-chain route table.
      const c1 = ctx();
      c1.inputs.options = c1.inputs.options.filter((o) => o.id === "B");
      expect(models(built(c1))).to.deep.equal(["EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION", "PER_CHAIN_ROUTE_TABLE"]);
      // One measured chain carries no cross-chain model, and the rules accept that answer.
      const c2 = ctx();
      c2.inputs.trustTargetSelection.requiredChains = ["1"];
      const r2 = built(c2);
      expect(r2.decisions.SP1_TRUST_TARGET_OPTION).to.equal("A");
      expect(models(r2)).to.deep.equal(["EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION", "UNRESOLVED"]);
      expect(rulesOf(r2)).to.deep.equal([]);
      // Nothing decided: nothing to upgrade or carry across chains.
      const c3 = ctx();
      c3.inputs.probeFacts.verifierRuntime.v610ForbiddenOpcodes = ["SSTORE"];
      expect(models(built(c3))).to.deep.equal(["UNRESOLVED", "UNRESOLVED"]);
      // An unpinned registry that were viable would route upgrades (the rules still refuse it).
      const c4 = ctx();
      c4.inputs.options = c4.inputs.options.filter((o) => o.id === "C");
      c4.inputs.probeFacts.C_walletwallGateway.adminAddRouteWidensAcceptedRelation = false;
      const r4 = built(c4);
      expect(models(r4)).to.deep.equal(["MUTABLE_ROUTING", "PER_CHAIN_ROUTE_TABLE"]);
      expectRule(r4, "option C: an unpinned route registry cannot be viable");
    });

    it("measures upstream's freezes: a batch with an unaffected version, and one incident response", function () {
      const timing = (r: Td1DecisionReceipt) => [
        r.upstreamTimeline.daysFromAdvisoryToFreeze,
        r.upstreamTimeline.advisedFreezeBatchedWithUnaffectedVersionSeconds,
        r.upstreamTimeline.brokenBuildFreezeHours,
      ];
      expect(timing(built())).to.deep.equal([181, 108, 21.4]);
      // Order-independent: Sepolia's freezes of the same versions are not mainnet's.
      const c1 = ctx();
      c1.timeline.events.reverse();
      expect(timing(built(c1))).to.deep.equal([181, 108, 21.4]);
      // The batch is a distance, whichever freeze came first.
      const c2 = ctx();
      const v5 = c2.timeline.events.find((e) => e.chainId === 1 && e.version === "v5.0.0")!;
      v5.timestamp += 216;
      expect(timing(built(c2))[1]).to.equal(108);
      // Uncorroborated events are not measurements.
      const c3 = ctx();
      c3.timeline.events.find((e) => e.chainId === 1 && e.version === "v5.0.0")!.providersAgree = false;
      c3.timeline.events.find((e) => e.event === "RouteFrozen" && e.selector === "0x2b4aeaf7")!.providersAgree = false;
      expect(timing(built(c3))).to.deep.equal([181, null, null]);
      const c4 = ctx();
      c4.timeline.events = c4.timeline.events.filter((e) => !(e.event === "RouteAdded" && e.selector === "0x2b4aeaf7"));
      expect(timing(built(c4))[2]).to.equal(null);
    });
  });

  describe("program identity: derivations respond to the facts", function () {
    it("designates the vendor identity and refuses the builder-dependent local build", function () {
      const r = built();
      const local = r.programIdentity.candidates.find((c) => c.decisionValue === "REPRODUCIBLE_REPO_BUILD")!;
      expect(local.established).to.equal(false);
      expect(local.reason).to.contain("/home/sirmrdrgod/.cargo");
      const dz = r.decisions.PROGRAM_VKEY_DESIGNATION;
      expect([dz.status, dz.vkey, dz.elfSha256, dz.elfBytes]).to.deep.equal([
        "DESIGNATED",
        VENDOR_VKEY,
        VENDOR_ELF,
        206504,
      ]);
      expect(dz.independentHosts).to.deep.equal(["developer-workstation", "github-hosted-runner"]);
      expect(dz.crossCheck).to.deep.include({ agreeing: 3, conflicting: 0 });
      expect(dz.doNotPin[0].vkey).to.equal("0x00516cd6333c30f52557608680aa5e10e228856610ce7cba616640af56a93bd7");
    });

    it("the remapped local build corroborates but can never be the canonical definition", function () {
      const r = built();
      expect(r.decisions.PROGRAM_VKEY_DESIGNATION.reproducedOutsideVendorImage).to.equal(true);
      const remap = r.programIdentity.candidates.find((c) => c.decisionValue === "OTHER_ESTABLISHED_PROCEDURE")!;
      expect(remap.established).to.equal(false);
      // Control: a remap build that did NOT reproduce the identity (it produced the local one) removes the
      // corroboration, not the decision.
      const c = ctx();
      const w = c.remap.builds.find((b) => b.id === "P-remap")!.programs["mldsa65-withdrawal"];
      w.elfSha256 = LOCAL_ELF;
      w.vkey = LOCAL_VKEY;
      const r2 = built(c);
      expect(r2.decisions.PROGRAM_VKEY_DESIGNATION.reproducedOutsideVendorImage).to.equal(false);
      expect(r2.claims.IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE.status).to.equal("NOT_ESTABLISHED");
      expect(r2.decisions.PROGRAM_IDENTITY_DECISION).to.equal("PINNED_VENDOR_BUILD");
    });

    it("one-host reproducibility does not establish the vendor procedure", function () {
      const c = ctx();
      c.sp1p1Identity.environments = c.sp1p1Identity.environments.filter((e) => e.hostId !== "github-hosted-runner");
      const r = built(c);
      expect(r.decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
      expect(r.decisions.PROGRAM_VKEY_DESIGNATION.status).to.equal("NOT_DESIGNATED");
      expect(r.decisions.REAL_PROOF_LANE_UNBLOCKED.value).to.equal(false);
      expect(rulesOf(r)).to.deep.equal([]);
    });

    it("an ELF with two vkeys anywhere is a contradiction that blocks the decision", function () {
      const c = ctx();
      c.sp1p1Identity.crossChecks!.vkeyFromElf!.results.push({
        source: "synthetic",
        program: "mldsa65-withdrawal",
        elfSha256: VENDOR_ELF,
        vkey: LOCAL_VKEY,
      });
      const r = built(c);
      expect(r.programIdentity.contradictions.length).to.equal(1);
      expect(r.decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });

    it("a split vendor family (two ELFs from the pinned image) blocks the decision", function () {
      const c = ctx();
      c.sp1p1Identity.environments.find((e) => e.id === "C-docker")!.programs["mldsa65-withdrawal"].elfSha256 =
        LOCAL_ELF;
      const r = built(c);
      expect(r.programIdentity.contradictions).to.include("family vendor-image produced 2 withdrawal ELFs");
      expect(r.decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });

    it("corroboration outside the image needs the same ELF, not only the same vkey", function () {
      const c = ctx();
      c.remap.builds.find((b) => b.id === "P-remap")!.programs["mldsa65-withdrawal"].elfSha256 = "ab".repeat(32);
      const r = built(c);
      expect(r.programIdentity.contradictions).to.deep.equal([]);
      expect(r.decisions.PROGRAM_VKEY_DESIGNATION.reproducedOutsideVendorImage).to.equal(false);
    });

    it("a cross-check role keeps a candidate non-canonical even over a family reproduced on two hosts", function () {
      const c = ctx();
      // Point the cross-check candidate at the vendor-image family, which IS reproduced on two hosts: the
      // pre-registered role, not the strength of the evidence, keeps it from defining PROGRAM_VKEY.
      c.inputs.programIdentitySelection.candidates.find(
        (x) => x.decisionValue === "OTHER_ESTABLISHED_PROCEDURE",
      )!.family = "vendor-image";
      const remap = built(c).programIdentity.candidates.find((x) => x.decisionValue === "OTHER_ESTABLISHED_PROCEDURE")!;
      expect(remap.established).to.equal(false);
      expect(remap.reason).to.equal("pre-registered as a cross-check only; never the canonical definition");
    });

    it("the image's linux/amd64 manifest and every build's platform must match the pinned index", function () {
      // A self-consistent manifest (its body hashes to its digest) that the pinned index does not list: only the
      // index-to-manifest join can refuse it. Changing the digest alone would be caught by the body hash first.
      const c1 = ctx();
      c1.image.linuxAmd64Manifest.digest = `sha256:${"1".repeat(64)}`;
      c1.image.linuxAmd64Manifest.bodySha256 = `sha256:${"1".repeat(64)}`;
      expect(built(c1).programIdentity.vendorImage.indexDigestVerified).to.equal(false);
      const c2 = ctx();
      c2.sp1p1Identity.environments.find((e) => e.id === "C-host")!.image!.platform = "linux/arm64";
      expect(built(c2).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });

    it("the vkey must be linked to the canonical ELF by the outside cross-check", function () {
      const c = ctx();
      c.sp1p1Identity.crossChecks!.vkeyFromElf!.results = c.sp1p1Identity.crossChecks!.vkeyFromElf!.results.filter(
        (x) => x.elfSha256 !== VENDOR_ELF,
      );
      const dz = built(c).decisions.PROGRAM_VKEY_DESIGNATION;
      expect(dz.status).to.equal("NOT_DESIGNATED");
      expect(dz.reason).to.contain("not linked to the canonical ELF");
    });

    it("an image reference by tag, or a digest the registry body does not hash to, is not pinned", function () {
      const c1 = ctx();
      c1.inputs.programIdentitySelection.canonicalProcedure.image = "ghcr.io/succinctlabs/sp1:v6.3.1";
      expect(built(c1).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
      const c2 = ctx();
      c2.image.pinnedIndex.bodySha256 = `sha256:${"0".repeat(64)}`;
      expect(built(c2).programIdentity.vendorImage.indexDigestVerified).to.equal(false);
      expect(built(c2).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });

    it("the canonical procedure scripts must be preserved byte for byte", function () {
      const c = ctx();
      c.fileHashes["evidence/zk/sp1-td1/canonical-procedure/host-build-in-container.sh"] = "0".repeat(64);
      expect(built(c).programIdentity.canonicalProcedureScriptsPreserved).to.equal(false);
      expect(built(c).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });

    it("a subject that differs from what the builds measured is not designated", function () {
      const c = ctx();
      c.workingTreeManifest[0].sha256 = "e".repeat(64);
      expect(built(c).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });

    it("SP1 pins or circuit version that disagree with the subject block the decision", function () {
      const c = ctx();
      c.inputs.programIdentitySelection.canonicalProcedure.sp1["sp1-sdk"] = "^6.3.1";
      expect(built(c).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
      // Agreement is not enough: a range pin is refused even when procedure and subject agree on it.
      const c2 = ctx();
      c2.inputs.programIdentitySelection.canonicalProcedure.sp1["sp1-sdk"] = "^6.3.1";
      c2.sp1p1Receipt.subject.sp1Pins["sp1-sdk"] = "^6.3.1";
      expect(built(c2).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
      const c3 = ctx();
      c3.inputs.programIdentitySelection.canonicalProcedure.sp1.circuitVersion = "v6.0.0";
      expect(built(c3).decisions.PROGRAM_IDENTITY_DECISION).to.equal("UNRESOLVED");
    });
  });

  describe("lane rules reject the over-claims they name, on the receipt alone", function () {
    let R: Td1DecisionReceipt;
    beforeEach(function () {
      R = clone(committed());
    });

    it("positive control: the committed receipt passes the rules", function () {
      expect(rulesOf(R)).to.deep.equal([]);
    });

    it("rejects an owner-mutable gateway classified as immutable", function () {
      option(R, "D").acceptedRelationMutableOutsideTimelock = false;
      expectRule(R, "option D: acceptedRelationMutableOutsideTimelock disagrees with its authorization levers");
      expectRule(R, "option D: an owner-mutable route registry cannot be classified immutable");
    });

    it("rejects a gateway whose owner was dropped from the authorization levers", function () {
      const d = option(R, "D");
      d.widen = d.widen.filter((l) => l.governed);
      expectRule(R, "option D: acceptedRelationMutableOutsideTimelock disagrees with its authorization levers");
      // Made self-consistent, the omission is still refused: the route registry is unpinned.
      d.acceptedRelationMutableOutsideTimelock = false;
      expectRule(R, "option D: an owner-mutable route registry cannot be classified immutable");
    });

    it("rejects a gateway option that denies having a route registry", function () {
      option(R, "D").routeRegistry = false;
      expectRule(R, "option D: routeRegistry disagrees with its accepted path");
    });
    it("rejects a route freeze treated as authorization widening", function () {
      const b = option(R, "B");
      b.widen.push({ ...b.disable[0], scope: "authorization" });
      expectRule(R, "option B: freezeRoute can only stop verification; it is not an authorization lever");
    });

    it("rejects a route addition treated as liveness-only", function () {
      const d = option(R, "D");
      const add = d.widen.find((l) => l.lever === "addRoute")!;
      d.disable.push({ ...add, scope: "liveness" });
      expectRule(R, "option D: addRoute widens the accepted relation; it cannot be classified liveness-only");
    });

    it("rejects a lever whose scope contradicts its list", function () {
      option(R, "A").widen[0].scope = "liveness";
      expectRule(R, "option A: widen lever pqVerifierRotation is not scoped authorization");
      R = clone(committed());
      option(R, "B").disable[0].scope = "authorization";
      expectRule(R, "option B: disable lever freezeRoute is not scoped liveness");
    });

    it("rejects an unpinned route registry marked viable", function () {
      option(R, "D").viable = true;
      option(R, "D").rejectedBecause = null;
      expectRule(R, "option D: an unpinned route registry cannot be viable");
      expectRule(R, "option D: an option with an external authorization lever cannot be viable");
    });

    it("rejects a fully pinned option marked viable while it carries an external authorization lever", function () {
      const b = option(R, "B");
      b.widen.push({ ...option(R, "D").widen.find((l) => l.lever === "addRoute")! });
      b.acceptedRelationMutableOutsideTimelock = true;
      expectRule(R, "option B: an option with an external authorization lever cannot be viable");
    });

    it("rejects an option whose viability and rejection reason disagree", function () {
      option(R, "A").rejectedBecause = "synthetic";
      expectRule(R, "option A: viable and rejectedBecause disagree");
    });

    it("rejects a direct immutable target whose code identity is not established", function () {
      R.trustTarget.established = false;
      expectRule(R, "a trust target cannot be decided while its code identity is not established");
      expectRule(R, "the real-proof lane cannot be unblocked before the trust target's code identity is established");
    });

    it("rejects a direct immutable target without matching verdicts on every chain", function () {
      R.trustTarget.chainExecution[2].verdictsAsExpected = false;
      expectRule(R, "a direct immutable target needs the same verdicts from the deployed template on every chain");
      R = clone(committed());
      R.trustTarget.chainExecution[0].providersAgree = false;
      expectRule(R, "a direct immutable target needs the same verdicts from the deployed template on every chain");
      R = clone(committed());
      R.trustTarget.chainExecution.pop();
      expectRule(R, "a direct immutable target needs the same verdicts from the deployed template on every chain");
    });

    it("rejects a direct immutable target recorded with mutable verifier code", function () {
      option(R, "A").verifierCodeMutable = true;
      expectRule(R, "a direct immutable target cannot have mutable verifier code");
    });

    it("rejects inconsistent decision bookkeeping", function () {
      R.decisions.SP1_TRUST_TARGET_DECISION = "UNRESOLVED";
      expectRule(R, "an UNRESOLVED trust target names no option");
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_OPTION = "Z";
      expectRule(R, "the trust-target decision names no evaluated option");
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "SELECTOR_PINNED_GATEWAY";
      expectRule(R, "the decided option's value differs from the decision");
    });

    it("rejects a direct immutable target with a reachable state write, unauthenticated initcode or split code", function () {
      R.trustTarget.runtime.forbiddenOpcodes = ["DELEGATECALL"];
      expectRule(R, "a direct immutable target cannot have reachable state- or code-changing opcodes");
      R = clone(committed());
      R.trustTarget.create2.authenticated = false;
      expectRule(R, "a direct immutable target needs CREATE2-authenticated initcode");
      R = clone(committed());
      R.trustTarget.chains[1].codeKeccak = `0x${"cd".repeat(32)}`;
      expectRule(R, "a direct immutable target needs one code hash on every chain");
    });

    it("rejects a decision for a non-viable option, or one that ignores a less-levered viable option", function () {
      R.decisions.SP1_TRUST_TARGET_DECISION = "UPSTREAM_GATEWAY_OWNER_ACCEPTED";
      R.decisions.SP1_TRUST_TARGET_OPTION = "D";
      expectRule(R, "the decided option D is not viable");
      expectRule(R, "the decided option D leaves an external authorization lever");
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "SELECTOR_PINNED_GATEWAY";
      R.decisions.SP1_TRUST_TARGET_OPTION = "B";
      expectRule(R, "a viable option with fewer external liveness levers exists (A)");
    });

    it("rejects one-host reproducibility", function () {
      const fam = R.programIdentity.families.find((f) => f.family === "vendor-image")!;
      fam.hosts = ["developer-workstation"];
      expectRule(R, "one-host reproducibility cannot define PROGRAM_VKEY");
      R = clone(committed());
      R.programIdentity.families.find((f) => f.family === "vendor-image")!.reproducedOnIndependentHosts = false;
      expectRule(R, "a canonical program identity needs one identity on independent hosts");
    });

    it("rejects a program-identity decision naming a candidate that is not established", function () {
      R.programIdentity.candidates.find((c) => c.decisionValue === "PINNED_VENDOR_BUILD")!.established = false;
      expectRule(R, "the program-identity decision names no established candidate");
    });

    it("rejects a resolved program identity without a designation, and a designation without its values", function () {
      R.decisions.PROGRAM_VKEY_DESIGNATION.status = "NOT_DESIGNATED";
      expectRule(R, "a resolved program identity must designate PROGRAM_VKEY");
      R = clone(committed());
      R.decisions.PROGRAM_VKEY_DESIGNATION.vkey = null;
      expectRule(R, "a designation needs the canonical ELF and its vkey");
    });

    it("rejects the local vkey chosen despite the canonical vendor designation", function () {
      R.decisions.PROGRAM_VKEY_DESIGNATION.vkey = LOCAL_VKEY;
      R.decisions.PROGRAM_VKEY_DESIGNATION.elfSha256 = LOCAL_ELF;
      expectRule(R, "the designated ELF/vkey is not the canonical family's identity");
      expectRule(R, "the designated vkey is a builder-dependent local identity");
    });

    it("rejects the ACVP program designated as PROGRAM_VKEY", function () {
      R.decisions.PROGRAM_VKEY_DESIGNATION.vkey = R.decisions.PROGRAM_VKEY_DESIGNATION.doNotPin[0].vkey;
      expectRule(R, "the designated vkey is a program a verifier must never pin");
    });

    it("rejects an ELF/vkey mismatch from the outside cross-check", function () {
      R.decisions.PROGRAM_VKEY_DESIGNATION.crossCheck.conflicting = 1;
      expectRule(R, "an outside cross-check computed another vkey for the canonical ELF");
    });

    it("rejects a dropped independent vkey cross-check", function () {
      R.decisions.PROGRAM_VKEY_DESIGNATION.crossCheck.agreeing = 0;
      expectRule(R, "the designated vkey is not linked to the canonical ELF by an outside cross-check");
    });

    it("rejects a mutable container tag in the designation", function () {
      R.decisions.PROGRAM_VKEY_DESIGNATION.image = "ghcr.io/succinctlabs/sp1:v6.3.1";
      expectRule(R, "the designation must reference the image by digest, never by tag");
    });

    it("rejects an unverified image digest", function () {
      R.programIdentity.vendorImage.indexDigestVerified = false;
      expectRule(R, "the vendor build must be pinned by a verified image digest");
    });

    it("rejects contradicting evidence under a canonical identity", function () {
      R.programIdentity.contradictions = ["synthetic"];
      expectRule(R, "a canonical program identity cannot carry contradicting evidence");
    });

    it("rejects a cross-check procedure promoted to the canonical definition", function () {
      R.decisions.PROGRAM_IDENTITY_DECISION = "OTHER_ESTABLISHED_PROCEDURE";
      const cand = R.programIdentity.candidates.find((c) => c.decisionValue === "OTHER_ESTABLISHED_PROCEDURE")!;
      cand.established = true;
      expectRule(R, "a cross-check procedure cannot define PROGRAM_VKEY");
    });

    it("rejects an upgrade from UNRESOLVED to a designation without evidence", function () {
      R.decisions.PROGRAM_IDENTITY_DECISION = "UNRESOLVED";
      expectRule(R, "PROGRAM_VKEY cannot be designated while program identity is UNRESOLVED");
      expectRule(R, "CANONICAL_PROGRAM_IDENTITY cannot be ESTABLISHED while the decision is UNRESOLVED");
      expectRule(R, "the real-proof lane cannot be unblocked without a canonical program identity");
    });

    it("rejects the real-proof lane unblocked while the trust target is unresolved", function () {
      R.decisions.SP1_TRUST_TARGET_DECISION = "UNRESOLVED";
      R.decisions.SP1_TRUST_TARGET_OPTION = null;
      expectRule(R, "the real-proof lane cannot be unblocked with an UNRESOLVED trust target");
    });

    it("rejects the real-proof lane unblocked on a mutable target or without a designation", function () {
      R.decisions.SP1_TRUST_TARGET_DECISION = "UPSTREAM_GATEWAY_OWNER_ACCEPTED";
      R.decisions.SP1_TRUST_TARGET_OPTION = "D";
      expectRule(R, "the real-proof lane cannot be unblocked on a mutable trust target");
      R = clone(committed());
      R.decisions.PROGRAM_VKEY_DESIGNATION.status = "NOT_DESIGNATED";
      expectRule(R, "the real-proof lane cannot be unblocked without a designated PROGRAM_VKEY");
      R = clone(committed());
      R.trustTarget.circuitVersionMatchesSubject = false;
      expectRule(R, "the real-proof lane needs the target circuit to match the subject's SP1 version");
    });

    it("rejects a verdict that disagrees with the two decisions", function () {
      R.verdict = "STOP_NO_DESIGN_JUSTIFIED";
      expectRule(R, "verdict STOP_NO_DESIGN_JUSTIFIED disagrees with the decisions (DESIGN_DECIDED)");
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "UNRESOLVED";
      R.decisions.SP1_TRUST_TARGET_OPTION = null;
      expectRule(R, "verdict DESIGN_DECIDED disagrees with the decisions (PARTIAL_DECISION)");
      R.decisions.PROGRAM_IDENTITY_DECISION = "UNRESOLVED";
      expectRule(R, "verdict DESIGN_DECIDED disagrees with the decisions (STOP_NO_DESIGN_JUSTIFIED)");
      R = clone(committed());
      R.decisions.PROGRAM_IDENTITY_DECISION = "UNRESOLVED";
      expectRule(R, "verdict DESIGN_DECIDED disagrees with the decisions (PARTIAL_DECISION)");
    });

    it("rejects an authorization lever marked protective", function () {
      option(R, "D").widen.find((l) => l.lever === "addRoute")!.protectiveOnVerifierDefect = true;
      expectRule(R, "option D: authorization lever addRoute cannot be marked protective");
    });

    it("rejects an upgrade property the route registry and pins contradict", function () {
      option(R, "A").requiresRedeployToUpgrade = false;
      expectRule(R, "option A: requiresRedeployToUpgrade disagrees with its route registry and pins");
      R = clone(committed());
      option(R, "D").requiresRedeployToUpgrade = true;
      expectRule(R, "option D: requiresRedeployToUpgrade disagrees with its route registry and pins");
      R = clone(committed());
      option(R, "B").requiresRedeployToUpgrade = false;
      expectRule(R, "option B: requiresRedeployToUpgrade disagrees with its route registry and pins");
    });

    it("rejects a decided target on a chain read a second provider does not corroborate", function () {
      R.trustTarget.chains[3].providersAgree = false;
      expectRule(R, "a trust target cannot be decided on a chain read that a second provider does not corroborate");
    });

    it("rejects a direct target whose verdict could depend on more than the call", function () {
      R.trustTarget.runtime.reachableEnvironmentReads = { EXTCODESIZE: 1, BALANCE: 1 };
      expectRule(R, "a direct immutable target cannot read state or environment beyond its own code size");
      R = clone(committed());
      R.trustTarget.runtime.constantCallTargets = ["0x02", "0x08"];
      expectRule(R, "a direct immutable target may call only the BN254/modexp precompiles at constant addresses");
      R = clone(committed());
      R.trustTarget.runtime.metadataIsSolcCbor = false;
      expectRule(R, "a direct immutable target's opcode scan needs solc's CBOR metadata to bound the code");
    });

    it("rejects a direct target, or a real-proof claim, without a real proof on the pinned key", function () {
      R.trustTarget.realProofOnPinnedKey.established = false;
      expectRule(R, "a direct immutable target needs a real proof verified on its pinned key");
      expectRule(
        R,
        "PINNED_VERIFYING_KEY_REAL_PROOF cannot be ESTABLISHED without a real proof verified on the pinned key",
      );
    });

    it("rejects upgrade and cross-chain models that the decided option and the evidence do not carry", function () {
      R.decisions.UPGRADE_MODEL = "MUTABLE_ROUTING";
      expectRule(
        R,
        "UPGRADE_MODEL MUTABLE_ROUTING disagrees with the decided option (EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION)",
      );
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "UNRESOLVED";
      R.decisions.SP1_TRUST_TARGET_OPTION = null;
      expectRule(
        R,
        "UPGRADE_MODEL EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION disagrees with the decided option (UNRESOLVED)",
      );
      expectRule(
        R,
        "CROSS_CHAIN_MODEL CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK disagrees with the evidence (UNRESOLVED)",
      );
      R = clone(committed());
      R.decisions.CROSS_CHAIN_MODEL = "PER_CHAIN_ROUTE_TABLE";
      expectRule(
        R,
        "CROSS_CHAIN_MODEL PER_CHAIN_ROUTE_TABLE disagrees with the evidence (CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK)",
      );
      const unresolved =
        "CROSS_CHAIN_MODEL CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK disagrees with the evidence (UNRESOLVED)";
      const breaks: ((r: Td1DecisionReceipt) => void)[] = [
        (r) => r.trustTarget.chainExecution.splice(1),
        (r) => (r.trustTarget.chainExecution[1].verdictsAsExpected = false),
        (r) => (r.trustTarget.chainExecution[1].providersAgree = false),
        (r) => (r.trustTarget.established = false),
      ];
      for (const breakIt of breaks) {
        R = clone(committed());
        breakIt(R);
        expectRule(R, unresolved);
      }
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "SELECTOR_PINNED_GATEWAY";
      R.decisions.SP1_TRUST_TARGET_OPTION = "B";
      expectRule(
        R,
        "CROSS_CHAIN_MODEL CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK disagrees with the evidence (PER_CHAIN_ROUTE_TABLE)",
      );
    });

    it("rejects a defect response that drops or bends the open owner decision", function () {
      const dc = () => R.decisions.DEFECT_RESPONSE_COUPLING;
      (dc() as { status: string }).status = "NOT_APPLICABLE";
      expectRule(R, "viable fail-closed alternatives (AF, B) make the defect response an owner decision");
      R = clone(committed());
      dc().viableAlternatives = dc().viableAlternatives.filter((a) => a.id !== "B");
      expectRule(R, "DEFECT_RESPONSE_COUPLING must list exactly the viable fail-closed alternatives");
      // AF offered, B unoffered: B is dominated (same principals, longer path). Unoffer AF too and both are missing.
      R = clone(committed());
      expect(rulesOf(R).some((e) => e.includes("realized by option B"))).to.equal(false);
      dc().choices[1].options = [];
      expectRule(R, "the owner decision offers no choice realized by option AF");
      expectRule(R, "the owner decision offers no choice realized by option B");
      R = clone(committed());
      dc().choices = dc().choices.slice(1);
      expectRule(R, "the owner decision offers no choice realized by option A");
      R = clone(committed());
      dc().recommendation = "SOMETHING_ELSE";
      expectRule(R, "the owner decision's recommendation is not one of its choices");
      R = clone(committed());
      dc().requiredBeforeRealValue = false;
      expectRule(R, "the defect response must be required before real value");
      R = clone(committed());
      delete (R.decisions as Partial<Td1DecisionReceipt["decisions"]>).DEFECT_RESPONSE_COUPLING;
      expectRule(R, "DEFECT_RESPONSE_COUPLING is required");
    });

    it("lets an alternative go unoffered only behind an offered one with the same principals and a shorter path", function () {
      const missingB = "the owner decision offers no choice realized by option B";
      // B as short as AF: no longer dominated.
      option(R, "B").path = option(R, "AF").path.slice();
      expectRule(R, missingB);
      // B held by another principal: no longer dominated.
      R = clone(committed());
      option(R, "B").disable[0].principal = "upstream gateway owner 0x0000000000000000000000000000000000000001";
      expectRule(R, missingB);
    });

    it("rejects the reviewer's drop: freezes recorded as not protective, the decision marked not applicable", function () {
      for (const id of ["AF", "B"]) for (const l of option(R, id).disable) l.protectiveOnVerifierDefect = false;
      (R.decisions.DEFECT_RESPONSE_COUPLING as { status: string }).status = "NOT_APPLICABLE";
      R.decisions.DEFECT_RESPONSE_COUPLING.viableAlternatives = [];
      expectRule(R, "option B: freezeRoute must be recorded protective");
      expectRule(R, "option AF: freezeRoute must be recorded protective");
    });

    it("records a freeze as protective exactly when it freezes the pinned verifier's own route", function () {
      // A freeze-bit reader without the route pin may be coupled to another verifier's route: not protective.
      option(R, "AF").pins = option(R, "AF").pins.filter((p) => p !== "routeVerifier");
      expectRule(R, "option AF: freezeRoute must be recorded not protective");
      // The WalletWall gateway's own freeze stops the routed proofs too.
      R = clone(committed());
      option(R, "C").disable[0].protectiveOnVerifierDefect = false;
      expectRule(R, "option C: gatewayAdminFreezeRoute must be recorded protective");
    });

    it("rejects an option that reads the upstream gateway but records no freeze of its owners", function () {
      option(R, "AF").disable = [];
      expectRule(R, "option AF: an option that reads the upstream gateway must record its owners' freeze");
      R = clone(committed());
      option(R, "D").disable = [];
      expectRule(R, "option D: an option that reads the upstream gateway must record its owners' freeze");
    });

    it("rejects per-chain entries that are not the measured chains, once each", function () {
      for (const e of R.trustTarget.chainExecution) e.chainId = "1";
      expectRule(R, "the per-chain execution entries must be exactly the measured chains");
    });

    it("rejects a direct target whose per-chain calls are unbound or whose canary has no positive control", function () {
      R.trustTarget.chainCallsBound = false;
      expectRule(R, "a direct immutable target needs per-chain verdicts for the calls this receipt names");
      R = clone(committed());
      R.trustTarget.canaryHasPositiveControl = false;
      expectRule(R, "a direct immutable target needs a canary shown to detect a missing pairing precompile");
    });

    it("requires the lane's real-proof preconditions word for word", function () {
      const p = () => R.decisions.REAL_PROOF_LANE_UNBLOCKED;
      p().preconditions = p().preconditions.filter((x) => !x.includes("DEFECT_RESPONSE_COUPLING"));
      expectRule(R, "the real-proof preconditions are not the lane's");
      // A negated sentence still names the decision, and is still refused.
      R = clone(committed());
      p().preconditions = p().preconditions.map((x) =>
        x.includes("DEFECT_RESPONSE_COUPLING") ? x.replace("needs", "does not need") : x,
      );
      expectRule(R, "the real-proof preconditions are not the lane's");
      expect(
        committed().decisions.REAL_PROOF_LANE_UNBLOCKED.preconditions.some((x) =>
          x.includes("DEFECT_RESPONSE_COUPLING"),
        ),
      ).to.equal(true);
    });

    it("holds the decided halt's outputs to its design, and real value blocked", function () {
      R.decisions.HALT_REVERSIBILITY = "REVERSIBLE";
      expectRule(R, "HALT_REVERSIBILITY disagrees with the halt design (ONE_WAY)");
      R = clone(committed());
      R.decisions.RECOVERY = "UNHALT_IN_PLACE";
      expectRule(R, "RECOVERY must be NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE");
      R = clone(committed());
      R.decisions.UPSTREAM_GATEWAY_OWNER = "WALLETWALL_AUTHORITY";
      expectRule(R, "the upstream gateway owner is not a WalletWall authority under the decided response");
      R = clone(committed());
      R.decisions.DEFECT_RESPONSE_MECHANISM = "UPSTREAM_ROUTE_FREEZE";
      expectRule(R, "DEFECT_RESPONSE_MECHANISM disagrees with the defect-response decision");
      R = clone(committed());
      (R.decisions as { REAL_VALUE_BLOCKER: string }).REAL_VALUE_BLOCKER = "NONE";
      expectRule(R, "REAL_VALUE_BLOCKER must be TD2_IMPLEMENTATION_NOT_YET_BUILT: a design lane cannot lift it");
      // While the decision is open, the blocker is the decision itself.
      R = clone(committed());
      (R.decisions.DEFECT_RESPONSE_COUPLING as { status: string }).status = "OWNER_DECISION_REQUIRED";
      expectRule(R, "REAL_VALUE_BLOCKER must be DEFECT_RESPONSE_COUPLING_UNDECIDED: a design lane cannot lift it");
    });

    it("refuses a recovery claim for every consumer while the multisig vault cannot recover (TD1-N11)", function () {
      const all =
        "RECOVERY must be NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE: it claims every consumer only once every consumer can recover";
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      expectRule(R, all);
      // Hiding the stranded consumer from the per-consumer table does not make the claim true.
      R = clone(committed());
      const dc = () => R.decisions.DEFECT_RESPONSE_COUPLING;
      dc().recoveryByConsumer = dc().recoveryByConsumer.filter((x) => x.consumer !== "WalletWallMultiSigVault");
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      expectRule(R, all);
      expectRule(R, "recoveryByConsumer must list each measured consumer once, with the halt's scope and gate");
      // Nor does marking it applied, or erasing it from the stranded list.
      R = clone(committed());
      dc().recoveryByConsumer.find((x) => x.consumer === "WalletWallMultiSigVault")!.halt = "APPLIED";
      expectRule(R, "recoveryByConsumer must list each measured consumer once, with the halt's scope and gate");
      R = clone(committed());
      dc().recoveryByConsumer.find((x) => x.consumer === "WalletWallMultiSigVault")!.gate = null;
      expectRule(R, "recoveryByConsumer must list each measured consumer once, with the halt's scope and gate");
      R = clone(committed());
      dc().consumersWithoutRecoveryPath = [];
      expectRule(R, "consumersWithoutRecoveryPath must be the consumers with no recovery route");
      // Applying the halt to the stranded consumer everywhere does not make it recover.
      R = clone(committed());
      const msv = () => dc().recoveryByConsumer.find((x) => x.consumer === "WalletWallMultiSigVault")!;
      dc().haltDesign!.haltScope = {
        applies: ["PolicyControlBridge", "StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"],
        excludedUntilRecoverable: [],
      };
      msv().halt = "APPLIED";
      msv().gate = null;
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      expectRule(R, all);
      // Nor does a route written in while it stays outside the halt.
      R = clone(committed());
      msv().route = "OWN_TIMELOCKED_ROTATION";
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      expectRule(R, all);
      // And a receipt that measured no consumer at all claims nothing for every consumer.
      R = clone(committed());
      dc().measuredConsumers = [];
      dc().recoveryByConsumer = [];
      dc().consumersWithoutRecoveryPath = [];
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      expectRule(R, all);
      // A route the rules do not know is no route: an applied consumer with one cannot carry the halt, and it counts
      // for no recovery claim.
      R = clone(committed());
      const bridge = () => dc().recoveryByConsumer.find((x) => x.consumer === "PolicyControlBridge")!;
      (bridge() as { route: string }).route = "SOMETHING_ELSE";
      expectRule(R, "recoveryByConsumer: PolicyControlBridge has an unknown route SOMETHING_ELSE");
      expectRule(R, "the halt may not be applied to PolicyControlBridge: it cannot leave a halted wrapper");
      R = clone(committed());
      dc().haltDesign!.haltScope = {
        applies: ["PolicyControlBridge", "StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"],
        excludedUntilRecoverable: [],
      };
      Object.assign(msv(), { route: "SOMETHING_ELSE", halt: "APPLIED", gate: null });
      dc().consumersWithoutRecoveryPath = [];
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      expectRule(R, all);
    });

    it("refuses the review's self-consistent hand edits: the multisig vault admitted, the bridge excluded", function () {
      const dc = () => R.decisions.DEFECT_RESPONSE_COUPLING;
      const row = (c: string) => dc().recoveryByConsumer.find((x) => x.consumer === c)!;
      // Every field agrees that the multisig vault rotates and is in the scope; its gate is still unbuilt.
      R.decisions.RECOVERY = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
      Object.assign(row("WalletWallMultiSigVault"), {
        route: "OWN_TIMELOCKED_ROTATION",
        rotationDelaySeconds: 172_800,
        halt: "APPLIED",
        gate: null,
      });
      dc().consumersWithoutRecoveryPath = [];
      dc().haltDesign!.haltScope = {
        applies: ["PolicyControlBridge", "StablecoinVaultSimulator", "WalletWallMultiSigVault", "WalletWallVault"],
        excludedUntilRecoverable: [],
      };
      dc().td2Requirements.find((r) => r.id === "TD2-COMMON-VERIFIER-HALT")!.excludedConsumersRefusedAHaltableWrapper =
        [];
      for (const e of [
        "WalletWallMultiSigVault may not be in the halt's scope before TD2-MULTISIG-ROTATION is built",
        "WalletWallMultiSigVault waits outside the halt for TD2-MULTISIG-ROTATION",
        "WalletWallMultiSigVault shows a recovery route before TD2-MULTISIG-ROTATION is built: the design no longer describes the code",
      ])
        expectRule(R, e);
      // The bridge marked stranded and parked under the multisig vault's gate.
      R = clone(committed());
      Object.assign(row("PolicyControlBridge"), {
        route: "NONE",
        halt: "EXCLUDED_UNTIL_RECOVERABLE",
        gate: "TD2-MULTISIG-ROTATION",
      });
      dc().consumersWithoutRecoveryPath = ["PolicyControlBridge", "WalletWallMultiSigVault"];
      const scope = dc().haltDesign!.haltScope;
      scope.applies = scope.applies.filter((c) => c !== "PolicyControlBridge");
      scope.excludedUntilRecoverable.push({
        consumer: "PolicyControlBridge",
        gate: "TD2-MULTISIG-ROTATION",
        interim: "NOT_BOUND_TO_THE_SP1_PATH",
        authorizedBy: "TD1-N11-PREREQUISITE",
      });
      dc().td2Requirements.find((r) => r.id === "TD2-COMMON-VERIFIER-HALT")!.excludedConsumersRefusedAHaltableWrapper =
        ["PolicyControlBridge", "WalletWallMultiSigVault"];
      expectRule(R, "PolicyControlBridge waits for TD2-MULTISIG-ROTATION, which is not its own gate");
    });

    it("keeps every frozen TD2 requirement, and the proposed rotation, on the record", function () {
      R.decisions.REAL_VALUE_REQUIREMENTS = ["TD2-COMMON-VERIFIER-HALT"];
      expectRule(
        R,
        "REAL_VALUE_REQUIREMENTS must name every requirement frozen for TD2: real value waits for all of them",
      );
      R = clone(committed());
      R.decisions.AUTHORIZATION_AUTHORITY_DELTA.proposedForTd2 = [];
      expectRule(R, "AUTHORIZATION_AUTHORITY_DELTA must carry every widening capability proposed for TD2");
      R = clone(committed());
      R.decisions.AUTHORIZATION_AUTHORITY_DELTA.proposedForTd2[0].classification = "AUTHORITY_NEUTRAL";
      expectRule(R, "AUTHORIZATION_AUTHORITY_DELTA must carry every widening capability proposed for TD2");
      // An undecided response freezes nothing, and real value waits on the decision itself.
      R = clone(committed());
      (R.decisions.DEFECT_RESPONSE_COUPLING as { status: string }).status = "OWNER_DECISION_REQUIRED";
      R.decisions.DEFECT_RESPONSE_COUPLING.td2Requirements = [];
      expectRule(
        R,
        "REAL_VALUE_REQUIREMENTS must name every requirement frozen for TD2: real value waits for all of them",
      );
    });

    it("rejects an authorization-neutral classification for a halt principal with widening power", function () {
      R.decisions.DEFECT_RESPONSE_COUPLING.haltDesign!.haltPrincipal.powers.push("WIDEN_ACCEPTED_RELATION");
      expect(R.decisions.AUTHORIZATION_AUTHORITY_DELTA.classification).to.equal("NO_NEW_AUTHORIZATION_PRINCIPAL");
      expectRule(R, "a halt principal with widening power is authority: the delta cannot be authorization-neutral");
      expectRule(R, "the halt principal may only halt (also holds: WIDEN_ACCEPTED_RELATION)");
    });

    it("refuses a decided path that gives the upstream gateway owner a lever", function () {
      // AF shares A's decision value; deciding it would put the gateway owners' freeze in the path.
      R.decisions.SP1_TRUST_TARGET_OPTION = "AF";
      expectRule(R, "the decided path gives the upstream gateway owner a lever");
      expectRule(R, "the owner's decision must be realized by the decided trust target");
    });

    it("states the authority every option inherits instead of claiming none", function () {
      const r = built();
      expect(r.decisions.AUTHORIZATION_AUTHORITY_DELTA.inheritedByEveryOption).to.equal(INHERITED_BY_EVERY_OPTION);
      expect(r.decisions.LIVENESS_DEPENDENCY.inheritedByEveryOption).to.equal(INHERITED_BY_EVERY_OPTION);
      expect(r.claims.DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER.basis).to.contain(`beyond ${INHERITED_BY_EVERY_OPTION}`);
      expect(INHERITED_BY_EVERY_OPTION).to.contain("each chain's own governance");
    });

    it("counts as fail-closed alternatives only viable, undecided options whose external levers all protect", function () {
      const listedExactly = "DEFECT_RESPONSE_COUPLING must list exactly the viable fail-closed alternatives";
      // A freeze recorded as not protective takes AF out of the trade-off.
      option(R, "AF").disable[0].protectiveOnVerifierDefect = false;
      expectRule(R, listedExactly);
      // Deciding B leaves AF as the only alternative: B is not its own, and A has no external lever to trade.
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "SELECTOR_PINNED_GATEWAY";
      R.decisions.SP1_TRUST_TARGET_OPTION = "B";
      R.decisions.DEFECT_RESPONSE_COUPLING.viableAlternatives =
        R.decisions.DEFECT_RESPONSE_COUPLING.viableAlternatives.filter((a) => a.id === "AF");
      expect(rulesOf(R)).to.not.include(listedExactly);
      expectRule(R, "a viable option with fewer external liveness levers exists (A)");
    });

    it("rejects proof, readiness, algorithm-independence and defect-response claims from a design lane", function () {
      for (const k of [
        "REAL_SP1_PROOF_GENERATED",
        "REAL_SP1_PROOF_VERIFIED",
        "PRODUCTION_READINESS",
        "VKEY_DERIVATION_ALGORITHM_INDEPENDENT",
        "DEFECT_RESPONSE_PATH",
      ] as const) {
        const r = clone(committed());
        r.claims[k].status = "ESTABLISHED";
        expectRule(r, `${k} cannot be claimed by a design lane`);
      }
    });

    it("rejects claim upgrades the evidence does not carry", function () {
      R.trustTarget.established = false;
      expectRule(R, "TRUST_TARGET_CODE_IDENTITY cannot be ESTABLISHED without the evidence");
      R = clone(committed());
      R.decisions.PROGRAM_VKEY_DESIGNATION.status = "NOT_DESIGNATED";
      expectRule(R, "PROGRAM_VKEY_DESIGNATED cannot be ESTABLISHED without a designation");
    });

    it("rejects a complete-route-history claim, and a reproduction claim without the reproduction", function () {
      R.claims.GATEWAY_ROUTE_HISTORY_COMPLETE.status = "ESTABLISHED";
      expectRule(
        R,
        "GATEWAY_ROUTE_HISTORY_COMPLETE cannot be ESTABLISHED: an indexer's event history is not a completeness proof",
      );
      R = clone(committed());
      R.decisions.PROGRAM_VKEY_DESIGNATION.reproducedOutsideVendorImage = false;
      expectRule(R, "IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE cannot be ESTABLISHED without the reproduction");
    });

    it("rejects a no-external-lever claim for a decided option that has one, or for no decided option", function () {
      const claim =
        "DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER cannot be ESTABLISHED while the decided option has an external lever";
      option(R, "A").disable.push({ ...option(R, "B").disable[0] });
      expectRule(R, claim);
      R = clone(committed());
      option(R, "A").widen.push({ ...option(R, "D").widen.find((l) => l.lever === "addRoute")! });
      expectRule(R, claim);
      R = clone(committed());
      R.decisions.SP1_TRUST_TARGET_DECISION = "UNRESOLVED";
      R.decisions.SP1_TRUST_TARGET_OPTION = null;
      expectRule(R, claim);
    });

    it("rejects unknown or missing structure", function () {
      (R as unknown as Record<string, unknown>).extra = 1;
      expectRule(R, "unknown top-level key extra");
      R = clone(committed());
      delete (R.claims as Partial<Record<string, unknown>>).PRODUCTION_READINESS;
      expectRule(R, "missing claim PRODUCTION_READINESS");
      expect(validateDecisionRules(null)).to.deep.equal(["receipt must be an object"]);
    });
  });

  describe("assurance document stays tied to the receipt", function () {
    const DOC = "docs/SP1_TD1_Trust_Target_Program_Identity.md";
    const doc = () => readFileSync(resolve(DOC), "utf8");
    function section(heading: string): string {
      const text = doc();
      const start = text.indexOf(`\n## ${heading}\n`);
      expect(start, `section "${heading}"`).to.not.equal(-1);
      const end = text.indexOf("\n## ", start + 4);
      return text.slice(start, end === -1 ? undefined : end);
    }
    const rows = (s: string) =>
      [...s.matchAll(/^\| `([A-Z_0-9]+)` \| `([A-Za-z_0-9]+)` \|/gm)].map((m) => [m[1], m[2]]);

    it("states exactly the receipt's claim statuses, in order", function () {
      const r = committed();
      const got = rows(section("Claim status"));
      expect(got.map(([k]) => k)).to.deep.equal([...TD1_CLAIM_KEYS]);
      for (const [k, s] of got) expect(s, k).to.equal(r.claims[k as Td1ClaimKey].status);
    });

    it("states exactly the receipt's decisions", function () {
      const d = committed().decisions;
      expect(rows(section("Decisions"))).to.deep.equal([
        ["SP1_TRUST_TARGET_DECISION", d.SP1_TRUST_TARGET_DECISION],
        ["PROGRAM_IDENTITY_DECISION", d.PROGRAM_IDENTITY_DECISION],
        ["UPGRADE_MODEL", d.UPGRADE_MODEL],
        ["CROSS_CHAIN_MODEL", d.CROSS_CHAIN_MODEL],
        ["DEFECT_RESPONSE_COUPLING", d.DEFECT_RESPONSE_COUPLING.decision ?? d.DEFECT_RESPONSE_COUPLING.status],
        ["DEFECT_RESPONSE_MECHANISM", d.DEFECT_RESPONSE_MECHANISM],
        ["AUTHORIZATION_AUTHORITY_DELTA", d.AUTHORIZATION_AUTHORITY_DELTA.classification],
        ["LIVENESS_AUTHORITY_DELTA", d.LIVENESS_AUTHORITY_DELTA.classification],
        ["HALT_REVERSIBILITY", d.HALT_REVERSIBILITY],
        ["RECOVERY", d.RECOVERY],
        ["UPSTREAM_GATEWAY_OWNER", d.UPSTREAM_GATEWAY_OWNER],
        ["REAL_VALUE_BLOCKER", d.REAL_VALUE_BLOCKER],
        ["REAL_PROOF_LANE_UNBLOCKED", String(d.REAL_PROOF_LANE_UNBLOCKED.value)],
        ["IMPLEMENTATION_REQUIRED", String(d.IMPLEMENTATION_REQUIRED.required)],
      ]);
      // The requirement ids are hyphenated, so their row is read on its own: every backticked value, in order.
      const req = /^\| `REAL_VALUE_REQUIREMENTS` \| (.*?) \|/m.exec(section("Decisions"));
      expect(req, "REAL_VALUE_REQUIREMENTS row").to.not.equal(null);
      expect([...req![1].matchAll(/`([^`]+)`/g)].map((m) => m[1])).to.deep.equal(d.REAL_VALUE_REQUIREMENTS);
    });

    it("states the authority accounting the receipt carries, principal by principal", function () {
      const a = committed().decisions.DEFECT_RESPONSE_COUPLING.authorityAccounting!;
      const table = doc()
        .split("\n")
        .filter((l) => /^\| `WALLETWALL_(?:EMERGENCY_HALT_PRINCIPAL|VAULT_OWNER|MULTISIG_VAULT_OWNER)`/.test(l));
      const accounted = [a.haltPrincipal, a.vaultOwnerToday, a.multisigOwnerToday, a.proposedMultisigRotation];
      expect(table.length).to.equal(accounted.length);
      accounted.forEach((x, i) => {
        const [principal, holds, scope, widens, status] = table[i].slice(2, -2).split(" | ");
        expect(principal, x.principal).to.contain(`\`${x.principal}\``);
        for (const c of x.capabilities) expect(holds, x.principal).to.contain(`\`${c}\``);
        expect(scope, x.principal).to.equal(x.scope);
        expect(widens.replace(/\*/g, ""), x.principal).to.equal(x.widensAuthorization ? "yes" : "no");
        for (const s of [x.status, x.classification].filter(Boolean))
          expect(status, x.principal).to.contain(`\`${s}\``);
      });
    });

    it("states each finding's disposition as the receipt records it", function () {
      const findings = section("Findings intersecting this design");
      for (const f of committed().findings) {
        const line = findings.split("\n").find((l) => l.startsWith(`| ${f.id} `));
        expect(line, f.id).to.not.equal(undefined);
        expect(line!.split(" | ")[1], f.id).to.equal(`\`${f.disposition}\``);
      }
    });

    it("names no full-length hash, vkey or address that the committed evidence does not contain", function () {
      const c = ctx();
      const sources = [
        TD1_RECEIPT_REL,
        TD1_INPUTS_REL,
        ...c.inputs.evidence.td1Observations.map((o) => o.path),
        c.inputs.evidence.sp1p1Receipt.path,
        ...c.inputs.evidence.sp1p1Observations.map((o) => o.path),
      ];
      const evidence = sources
        .map((p) => readFileSync(resolve(p), "utf8"))
        .join("\n")
        .toLowerCase();
      const tokens = [...new Set(doc().match(/\b(?:0x)?[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\b/g) ?? [])];
      expect(tokens.length).to.be.greaterThan(20);
      const missing = tokens.filter((t) => !evidence.includes(t.toLowerCase().replace(/^0x/, "")));
      expect(missing).to.deep.equal([]);
    });
  });
});
