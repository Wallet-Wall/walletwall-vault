/**
 * Tests for the SP1-TD1 decision receipt (scripts/lib/sp1-td1-decision.ts, evidence/zk/sp1-td1/): the committed
 * receipt re-derives from its inputs and observations; the derivations respond to the facts they consume
 * (positive and negative controls); and the lane rules reject every over-claim on their own, so a hand-edited
 * receipt cannot pass by being internally consistent.
 *
 * Pure, fast, static reads — no SP1 toolchain, no proving, no network. The probe facts themselves are executed
 * by test/Sp1Td1TrustTargetProbes.test.ts.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  TD1_CLAIM_KEYS,
  TD1_INPUTS_REL,
  TD1_RECEIPT_REL,
  buildDecisionReceipt,
  checkContextFresh,
  decideTrustTarget,
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
      expect(r.decisions.CROSS_CHAIN_MODEL).to.equal("CODE_HASH_PINNED_SAME_IDENTITY_ON_EVERY_CHAIN");
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

    it("ranks by authority minimisation: A over the viable pinned gateway, which carries external liveness levers", function () {
      const r = built();
      expect(option(r, "A").viable).to.equal(true);
      expect(option(r, "B").viable).to.equal(true);
      expect(decideTrustTarget(r.options)).to.deep.equal({ decision: "DIRECT_IMMUTABLE_VERIFIER", optionId: "A" });
      // Positive control for the tie-break: without A, the pinned gateway is the decision.
      expect(decideTrustTarget(r.options.filter((o) => o.id !== "A"))).to.deep.equal({
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

    it("a gateway with a set EIP-1967 slot is reported as code-mutable", function () {
      expect(option(built(), "D").gatewayCodeMutable).to.equal(false);
      const c = ctx();
      c.chain.chains["1"].gateway.eip1967ImplementationSlot = `0x${"0".repeat(63)}1`;
      expect(option(built(c), "D").gatewayCodeMutable).to.equal(true);
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

  describe("lane rules reject every over-claim on their own", function () {
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

    it("rejects proof, readiness and algorithm-independence claims from a design lane", function () {
      for (const k of [
        "REAL_SP1_PROOF_GENERATED",
        "REAL_SP1_PROOF_VERIFIED",
        "PRODUCTION_READINESS",
        "VKEY_DERIVATION_ALGORITHM_INDEPENDENT",
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
        ["REAL_PROOF_LANE_UNBLOCKED", String(d.REAL_PROOF_LANE_UNBLOCKED.value)],
        ["IMPLEMENTATION_REQUIRED", String(d.IMPLEMENTATION_REQUIRED.required)],
      ]);
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
