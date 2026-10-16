/**
 * Tests for the SP1-P1 assurance STOP receipt (scripts/lib/sp1-p1-stop-receipt.ts,
 * evidence/zk/sp1-p1/stop-receipt.json): the committed receipt re-derives from its observations, the
 * lane rules reject every over-claim on their own, drift and stale subjects are refused, and the identity
 * and gateway derivations are checked against synthetic positive and negative controls.
 *
 * Pure, fast, static reads — no SP1 toolchain, no proving, no network.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { expect } from "chai";

import {
  ACVP,
  CLAIM_KEYS,
  RECEIPT_REL,
  WITHDRAWAL,
  buildReceipt,
  checkInputsFresh,
  deriveGatewayVerdict,
  deriveProgramIdentityVerdict,
  deriveProgramIsolation,
  readObservationInputs,
  readSupersession,
  receiptInputsInRepo,
  sourceManifestDigest,
  SUPERSESSION_REL,
  validateCommittedReceipt,
  validateCommittedReceiptInRepo,
  validateReceiptRules,
  validateSupersession,
  type Supersession,
  type EnvironmentObservation,
  type ReceiptInputs,
  type Sp1P1StopReceipt,
  type VerifierGatewayObservations,
} from "../scripts/lib/sp1-p1-stop-receipt";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const committed = (): Sp1P1StopReceipt => JSON.parse(readFileSync(resolve(RECEIPT_REL), "utf8")) as Sp1P1StopReceipt;

let INPUTS: ReceiptInputs;
const inputs = (): ReceiptInputs => clone(INPUTS);

const HEX = (c: string) => c.repeat(64);
const uniqueTokens = (xs: string[]) => [...new Set(xs)];
function env(
  id: string,
  hostId: string,
  procedure: EnvironmentObservation["procedure"],
  w: [string, string | null],
  a: [string, string | null],
): EnvironmentObservation {
  return {
    id,
    hostId,
    procedure,
    description: "synthetic",
    os: null,
    kernel: null,
    measuredAtUtc: null,
    image: null,
    toolchain: {},
    builder: { home: null, embeddedCargoHome: null },
    sourceManifest: null,
    programs: {
      [WITHDRAWAL]: { elfSha256: w[0], elfBytes: 1, vkey: w[1] },
      [ACVP]: { elfSha256: a[0], elfBytes: 1, vkey: a[1] },
    },
    hostBinarySha256: null,
  };
}

describe("SP1-P1 assurance STOP receipt", function () {
  before(function () {
    // Superseded (TD1-N4): the repository bytes the receipt binds are read at its historical subject.
    INPUTS = receiptInputsInRepo();
  });

  describe("committed receipt", function () {
    it("validates against its observations, the subject sources and the lane rules", function () {
      expect(validateCommittedReceipt(committed(), inputs())).to.deep.equal([]);
    });

    it("is identical to a fresh derivation (no drift)", function () {
      expect(JSON.stringify(committed())).to.equal(JSON.stringify(buildReceipt(inputs())));
    });

    it("records a STOP with the Phase 1 identity conflict and the Phase 2 owner-mutable gateway", function () {
      const r = committed();
      expect(r.verdict).to.equal("STOP_DESIGN_ISSUE");
      const fired = r.stopConditions.filter((s) => s.triggered).map((s) => s.condition);
      expect(fired).to.include("two clean environments produce different withdrawal vkeys");
      expect(fired).to.include("program identity depends on unpinned mutable external state");
      expect(fired).to.include("the gateway is mutable in a way the current trust model does not account for");
      expect(fired).to.not.include("the actual verifier gateway cannot be independently attributed");
    });

    it("re-derives the subject source manifest (Node crypto) equal to every environment's coreutils digest", function () {
      const onDisk = sourceManifestDigest(inputs().sourceFiles);
      const measured = INPUTS.identity.environments.filter((e) => e.sourceManifest);
      expect(measured.length).to.be.greaterThan(1);
      for (const e of measured) expect(sourceManifestDigest(e.sourceManifest!)).to.equal(onDisk);
      expect(committed().subject.sourceManifestSha256).to.equal(onDisk);
    });

    it("leaves the proof, replay, readiness and conformance claims unclaimed", function () {
      const c = committed().claims;
      expect(c.REAL_SP1_PROOF_GENERATED.status).to.equal("NOT_ESTABLISHED");
      expect(c.REAL_SP1_PROOF_VERIFIED.status).to.equal("NOT_ESTABLISHED");
      expect(c.SP1_VERIFIER_GATEWAY_PROVENANCE.status).to.equal("NOT_ESTABLISHED");
      expect(c.CROSS_VAULT_REPLAY_RESISTANCE.status).to.equal("NOT_TESTED");
      expect(c.CROSS_CHAIN_REPLAY_RESISTANCE.status).to.equal("NOT_TESTED");
      expect(c.PRODUCTION_READINESS.status).to.equal("NOT_ESTABLISHED");
      expect(c.NIST_CONFORMANCE.status).to.equal("NOT_ESTABLISHED");
      expect(Object.keys(c)).to.deep.equal([...CLAIM_KEYS]);
      expect(committed().proof).to.equal(null);
    });

    it("never designates a canonical withdrawal identity: the derived verdict keeps every observed identity", function () {
      const r = committed();
      const groups = r.programIdentity.withdrawal.groups;
      expect(groups.length).to.be.greaterThan(1);
      expect(r.claims.CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY.status).to.not.equal("ESTABLISHED");
      expect(r.claims.CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY.status).to.equal(r.programIdentity.withdrawal.status);
    });
  });

  describe("assurance document stays tied to the receipt", function () {
    const DOC = "docs/SP1_P1_Gateway_Provenance_Stop.md";
    const doc = () => readFileSync(resolve(DOC), "utf8");

    it("states exactly the receipt's claim statuses", function () {
      const rows = [...doc().matchAll(/^\| `([A-Z_0-9]+)` \| `([A-Z_]+)` \|/gm)].map((m) => [m[1], m[2]]);
      const r = committed();
      expect(rows.map(([k]) => k)).to.deep.equal([...CLAIM_KEYS]);
      for (const [k, s] of rows) expect(s, k).to.equal(r.claims[k as (typeof CLAIM_KEYS)[number]].status);
    });

    it("names no full-length hash, vkey or address that the receipt or its observations do not contain", function () {
      const evidence = [
        readFileSync(resolve(RECEIPT_REL), "utf8"),
        ...INPUTS.observationFiles.map((o) => readFileSync(resolve(o.path), "utf8")),
      ]
        .join("\n")
        .toLowerCase();
      const tokens = uniqueTokens(doc().match(/\b(?:0x)?[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\b/g) ?? []);
      expect(tokens.length).to.be.greaterThan(20);
      const missing = tokens.filter((t) => !evidence.includes(t.toLowerCase().replace(/^0x/, "")));
      expect(missing).to.deep.equal([]);
    });
  });

  describe("lane rules reject each over-claim on their own", function () {
    const mutants: [string, (r: Sp1P1StopReceipt) => void, RegExp][] = [
      [
        "readiness upgraded",
        (r) => (r.claims.PRODUCTION_READINESS.status = "ESTABLISHED"),
        /PRODUCTION_READINESS must stay/,
      ],
      [
        "readiness partially upgraded",
        (r) => (r.claims.PRODUCTION_READINESS.status = "PARTIALLY_ESTABLISHED"),
        /PRODUCTION_READINESS must stay/,
      ],
      [
        "NIST conformance claimed",
        (r) => (r.claims.NIST_CONFORMANCE.status = "PARTIALLY_ESTABLISHED"),
        /NIST_CONFORMANCE cannot/,
      ],
      [
        "proof generation claimed without a proof",
        (r) => (r.claims.REAL_SP1_PROOF_GENERATED.status = "ESTABLISHED"),
        /REAL_SP1_PROOF_GENERATED requires a proof/,
      ],
      [
        "proof verification claimed without a proof",
        (r) => (r.claims.REAL_SP1_PROOF_VERIFIED.status = "PARTIALLY_ESTABLISHED"),
        /REAL_SP1_PROOF_VERIFIED requires a proof/,
      ],
      [
        "gateway provenance claimed while an owner exists",
        (r) => (r.claims.SP1_VERIFIER_GATEWAY_PROVENANCE.status = "ESTABLISHED"),
        /cannot be ESTABLISHED while a measured gateway has an owner/,
      ],
      [
        "cross-environment claim diverges from its derivation",
        (r) => (r.claims.CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY.status = "ESTABLISHED"),
        /must equal the derived withdrawal identity verdict/,
      ],
      [
        "cross-vault replay claimed without a real proof",
        (r) => (r.claims.CROSS_VAULT_REPLAY_RESISTANCE.status = "ESTABLISHED"),
        /CROSS_VAULT_REPLAY_RESISTANCE cannot be claimed/,
      ],
      [
        "cross-chain replay claimed without a real proof",
        (r) => (r.claims.CROSS_CHAIN_REPLAY_RESISTANCE.status = "PARTIALLY_ESTABLISHED"),
        /CROSS_CHAIN_REPLAY_RESISTANCE cannot be claimed/,
      ],
      [
        "a claim dropped",
        (r) => delete (r.claims as Partial<Sp1P1StopReceipt["claims"]>).NIST_CONFORMANCE,
        /missing claim NIST_CONFORMANCE/,
      ],
      [
        "an unknown status",
        (r) => ((r.claims.WITHDRAWAL_PROGRAM_RELATION as { status: string }).status = "LIKELY"),
        /invalid status LIKELY/,
      ],
      [
        "an unknown claim",
        (r) =>
          ((r.claims as Record<string, unknown>).GATEWAY_IS_FINE = { status: "ESTABLISHED", basis: "x".repeat(30) }),
        /unknown claim GATEWAY_IS_FINE/,
      ],
      ["a claim without basis", (r) => (r.claims.ACVP_WITHDRAWAL_PROGRAM_ISOLATION.basis = "ok"), /needs a basis/],
      [
        "verdict softened while a stop condition fired",
        (r) => ((r as { verdict: string }).verdict = "PASS"),
        /requires verdict STOP_DESIGN_ISSUE/,
      ],
      [
        "a proof slot filled in this schema",
        (r) => ((r as { proof: unknown }).proof = { bytes: "0x00" }),
        /records no proof/,
      ],
      [
        "an extra top-level key",
        (r) => ((r as unknown as Record<string, unknown>).canonicalVkey = "0x00"),
        /unknown top-level key canonicalVkey/,
      ],
      [
        "the wrong schema",
        (r) => ((r as { schema: string }).schema = "walletwall.sp1-p1-stop-receipt.v0"),
        /schema must be/,
      ],
    ];
    for (const [name, mutate, rule] of mutants) {
      it(`kills: ${name}`, function () {
        expect(validateReceiptRules(committed()), "positive control").to.deep.equal([]);
        const r = clone(committed());
        mutate(r);
        const errors = validateReceiptRules(r);
        expect(
          errors.some((e) => rule.test(e)),
          errors.join(" | "),
        ).to.equal(true);
      });
    }
  });

  describe("superseded, never restamped (SP1-TD1 finding TD1-N4)", function () {
    const receiptBytes = () => readFileSync(resolve(RECEIPT_REL));
    const record = () => clone(readSupersession() as Supersession);

    it("the committed receipt validates in this repository as a superseded record", function () {
      expect(validateCommittedReceiptInRepo()).to.deep.equal([]);
      expect(validateSupersession(record(), receiptBytes())).to.deep.equal([]);
    });

    it("refuses a supersession record that is not an object", function () {
      for (const value of [42, "superseded", true]) {
        expect(validateSupersession(value, receiptBytes()), String(value)).to.deep.equal([
          "the supersession record is not an object",
        ]);
      }
    });

    it("a tree without a supersession record reads as not superseded, never as an empty record", function () {
      const dir = mkdtempSync(join(tmpdir(), "sp1-p1-"));
      try {
        expect(readSupersession(dir)).to.equal(null);
        mkdirSync(join(dir, dirname(SUPERSESSION_REL)), { recursive: true });
        writeFileSync(join(dir, SUPERSESSION_REL), JSON.stringify({ finding: "TD1-N4" }));
        expect(readSupersession(dir)).to.deep.equal({ finding: "TD1-N4" });
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("the in-repository validation refuses a bad supersession, and without one the receipt is not valid live", function () {
      const bad = record();
      bad.receiptSha256 = HEX("0");
      expect(validateCommittedReceiptInRepo(".", bad).join(" | ")).to.match(/never restamped/);
      expect(validateCommittedReceiptInRepo(".", null).join(" | ")).to.match(/ZKMLDSAVerifier\.sol changed/);
    });

    it("the validator CLI reports the superseded receipt valid", function () {
      const run = spawnSync(
        process.execPath,
        ["--import", "tsx", "scripts/generate-sp1-p1-stop-receipt.ts", "--validate"],
        {
          encoding: "utf8",
        },
      );
      expect(run.status, run.stderr).to.equal(0);
      expect(run.stdout).to.include(`superseded: bindings checked at its historical subject, ${SUPERSESSION_REL}`);
    });

    it("the tripwire really fired: the working tree's ZKMLDSAVerifier.sol no longer matches the binding, its historical subject does", function () {
      const live = validateCommittedReceipt(committed(), readObservationInputs());
      expect(live.join(" | ")).to.match(/ZKMLDSAVerifier\.sol changed/);
      const s = record();
      expect(readObservationInputs(".", s.historicalSubject).zkMldsaVerifierSha256).to.equal(
        committed().repositoryBindings.zkMldsaVerifierSha256,
      );
    });

    it("the historical reading is git's, file by file: at an older commit the zkvm manifest and the runbook differ", function () {
      // 779c7f06: the guest before the withdrawal-relation remediation (5e09486), its lockfile and sources older.
      const older = readObservationInputs(".", "779c7f0676bc8bd9e327a0cf8fe3f7e89822ec7d");
      const live = readObservationInputs(".");
      expect(sourceManifestDigest(older.sourceFiles)).to.not.equal(sourceManifestDigest(live.sourceFiles));
      expect(older.sourceFiles.map((f) => f.path)).to.include("zkvm/guest/Cargo.lock");
      expect(older.zkMldsaVerifierSha256).to.not.equal(live.zkMldsaVerifierSha256);
      // Positive control: at the historical subject the reading reproduces the receipt's own bindings.
      const at = readObservationInputs(".", record().historicalSubject);
      expect(at.sourceFiles).to.deep.equal(committed().repositoryBindings.sourceFiles);
      expect(at.proverRunbookDirectsToGateway).to.equal(true);
    });

    it("pins the receipt bytes and names its superseding records, SP1-TD1 first", function () {
      const s = record();
      expect(s.receipt).to.equal(RECEIPT_REL);
      expect(s.finding).to.equal("TD1-N4");
      expect(s.supersededBy.map((r) => r.lane)).to.deep.equal(["SP1-TD1", "SP1-TD2"]);
      expect(s.supersededBy[0].record).to.equal("evidence/zk/sp1-td1/decision-receipt.json");
    });

    it("refuses a restamped receipt, a foreign record and a subject where the receipt was not live", function () {
      const cases: [string, (s: Supersession) => void, RegExp][] = [
        ["another schema", (s) => (s.schema = "walletwall.sp1-p1-supersession.v0"), /schema must be/],
        ["another receipt", (s) => (s.receipt = "evidence/zk/sp1-td1/decision-receipt.json"), /must name/],
        ["another finding", (s) => (s.finding = "TD1-N5"), /must cite TD1-N4/],
        ["restamped bytes", (s) => (s.receiptSha256 = HEX("0")), /never restamped/],
        ["not a commit id", (s) => (s.historicalSubject = "main"), /full commit id/],
        [
          "a commit before the receipt existed",
          (s) => (s.historicalSubject = "6463caee352beda7a27009d29f1a48b42b063fd8"),
          /not in the repository at 6463caee/,
        ],
        [
          "a commit with earlier receipt bytes",
          // d75c091: the receipt's first commit, before the common-mode cross-checks changed it.
          (s) => (s.historicalSubject = "d75c091b693e48022b4238d8b08a37f720c21f47"),
          /is not the committed receipt/,
        ],
        ["no superseding record", (s) => (s.supersededBy = []), /at least one/],
        ["SP1-TD1 not first", (s) => s.supersededBy.reverse(), /first superseding record is SP1-TD1/],
        ["a record that does not exist", (s) => (s.supersededBy[1].record = "docs/NOPE.md"), /does not exist/],
        ["a record without a reason", (s) => (s.supersededBy[1].reason = ""), /a lane and a reason/],
      ];
      for (const [label, mutate, rule] of cases) {
        const s = record();
        mutate(s);
        expect(validateSupersession(s, receiptBytes()).join(" | "), label).to.match(rule);
      }
    });

    it("the generator refuses to rewrite a superseded receipt", function () {
      const run = spawnSync(process.execPath, ["--import", "tsx", "scripts/generate-sp1-p1-stop-receipt.ts"], {
        encoding: "utf8",
      });
      expect(run.status).to.not.equal(0);
      expect(run.stderr).to.include(`superseded (${SUPERSESSION_REL}) and is never restamped`);
      expect(readFileSync(resolve(RECEIPT_REL)).equals(receiptBytes())).to.equal(true);
    });
  });

  describe("drift and stale subjects are refused", function () {
    it("observation bytes changed after generation", function () {
      const i = inputs();
      i.observationFiles[0].sha256 = HEX("0");
      expect(validateCommittedReceipt(committed(), i).join(" | ")).to.match(/observation files changed/);
    });

    it("subject sources changed on disk (stale; no silent rebind)", function () {
      const i = inputs();
      i.sourceFiles[0].sha256 = HEX("0");
      expect(checkInputsFresh(i).join(" | ")).to.match(/stale: zkvm guest\/host sources on disk/);
      expect(checkInputsFresh(inputs())).to.deep.equal([]);
    });

    it("ZKMLDSAVerifier.sol changed after adjudication", function () {
      const i = inputs();
      i.zkMldsaVerifierSha256 = HEX("1");
      expect(validateCommittedReceipt(committed(), i).join(" | ")).to.match(/ZKMLDSAVerifier\.sol changed/);
    });

    it("the runbook no longer directs SP1_VERIFIER_ADDRESS at the gateway (premise changed)", function () {
      const i = inputs();
      i.proverRunbookDirectsToGateway = false;
      expect(checkInputsFresh(i).join(" | ")).to.match(/premise changed/);
    });

    it("a hand-edited measurement in the receipt", function () {
      const r = clone(committed());
      r.programIdentity.environments[0].withdrawal.vkey = r.programIdentity.environments[1].withdrawal.vkey;
      expect(validateCommittedReceipt(r, inputs()).join(" | ")).to.match(/drifted from the generator/);
    });
  });

  describe("program identity derivation", function () {
    const W1: [string, string] = [HEX("a"), `0x${HEX("1")}`];
    const W2: [string, string] = [HEX("b"), `0x${HEX("2")}`];
    const A1: [string, string] = [HEX("c"), `0x${HEX("3")}`];

    it("same-host rebuilds never count as independent reproduction", function () {
      const v = deriveProgramIdentityVerdict(
        [
          env("x", "h1", "vendor-image-host-flow", W1, A1),
          env("y", "h1", "vendor-image-docker-mode", [W1[0], null], [A1[0], null]),
        ],
        WITHDRAWAL,
      );
      expect(v.status).to.equal("NOT_ESTABLISHED");
    });

    it("one identity on two independent hosts is ESTABLISHED (positive control)", function () {
      const v = deriveProgramIdentityVerdict(
        [env("x", "h1", "vendor-image-host-flow", W1, A1), env("y", "h2", "vendor-image-host-flow", W1, A1)],
        WITHDRAWAL,
      );
      expect(v.status).to.equal("ESTABLISHED");
    });

    it("a family reproduced across hosts next to a conflicting procedure is only PARTIALLY_ESTABLISHED", function () {
      const v = deriveProgramIdentityVerdict(
        [
          env("a", "h1", "repository-host-flow-local", W2, A1),
          env("b", "h1", "vendor-image-host-flow", W1, A1),
          env("c", "h2", "vendor-image-docker-mode", [W1[0], null], [A1[0], null]),
        ],
        WITHDRAWAL,
      );
      expect(v.status).to.equal("PARTIALLY_ESTABLISHED");
      expect(v.families["vendor-image"].reproducedAcrossIndependentHosts).to.equal(true);
      expect(v.families["repository-local"].reproducedAcrossIndependentHosts).to.equal(false);
    });

    it("one ELF with two vkeys is a contradiction", function () {
      const v = deriveProgramIdentityVerdict(
        [
          env("x", "h1", "vendor-image-host-flow", W1, A1),
          env("y", "h2", "vendor-image-host-flow", [W1[0], W2[1]], A1),
        ],
        WITHDRAWAL,
      );
      expect(v.status).to.equal("NOT_ESTABLISHED");
      expect(v.contradictions.join(" ")).to.match(/maps to 2 vkeys/);
    });

    it("one vkey claimed by two ELFs is a contradiction", function () {
      const v = deriveProgramIdentityVerdict(
        [
          env("x", "h1", "vendor-image-host-flow", W1, A1),
          env("y", "h2", "vendor-image-host-flow", [W2[0], W1[1]], A1),
        ],
        WITHDRAWAL,
      );
      expect(v.contradictions.join(" ")).to.match(/claimed by 2 ELFs/);
      expect(v.status).to.equal("NOT_ESTABLISHED");
    });

    it("the committed observations re-derive the committed verdicts", function () {
      const r = committed();
      const xc = INPUTS.identity.crossChecks?.vkeyFromElf?.results ?? [];
      expect(deriveProgramIdentityVerdict(INPUTS.identity.environments, WITHDRAWAL, xc)).to.deep.equal(
        r.programIdentity.withdrawal,
      );
      expect(deriveProgramIdentityVerdict(INPUTS.identity.environments, ACVP, xc)).to.deep.equal(
        r.programIdentity.acvp,
      );
    });

    it("the out-of-environment cargo-prove cross-check covers and agrees with every observed identity", function () {
      const r = committed();
      for (const v of [r.programIdentity.withdrawal, r.programIdentity.acvp]) {
        expect(v.contradictions).to.deep.equal([]);
        for (const g of v.groups) {
          expect(g.vkeyCrossChecked, `${v.program} ${g.elfSha256}`).to.equal(true);
          expect(g.vkeys.length, `${v.program} ${g.elfSha256}`).to.equal(1);
        }
      }
      expect(r.programIdentity.vkeyCrossCheck?.tool).to.match(/^cargo-prove sp1 \(8252c29 /);
    });

    it("a cross-check that disagrees with an environment's vkey is a contradiction", function () {
      const envs = [env("x", "h1", "vendor-image-host-flow", W1, A1), env("y", "h2", "vendor-image-host-flow", W1, A1)];
      expect(deriveProgramIdentityVerdict(envs, WITHDRAWAL).status, "positive control").to.equal("ESTABLISHED");
      const v = deriveProgramIdentityVerdict(envs, WITHDRAWAL, [
        { source: "z", program: WITHDRAWAL, elfSha256: W1[0], vkey: W2[1] },
      ]);
      expect(v.status).to.equal("NOT_ESTABLISHED");
      expect(v.contradictions.join(" ")).to.match(/maps to 2 vkeys/);
    });

    it("a cross-check of an ELF no environment produced is a contradiction", function () {
      const envs = [env("x", "h1", "vendor-image-host-flow", W1, A1), env("y", "h2", "vendor-image-host-flow", W1, A1)];
      const v = deriveProgramIdentityVerdict(envs, WITHDRAWAL, [
        { source: "z", program: WITHDRAWAL, elfSha256: W2[0], vkey: W2[1] },
      ]);
      expect(v.status).to.equal("NOT_ESTABLISHED");
      expect(v.contradictions.join(" ")).to.match(/that no environment produced/);
    });
  });

  describe("withdrawal / ACVP program isolation", function () {
    it("holds for the committed observations", function () {
      expect(deriveProgramIsolation(INPUTS.identity.environments)).to.deep.equal({ holds: true, violations: [] });
    });

    it("detects a shared ELF inside one environment, and names it as such", function () {
      const e = env("x", "h1", "vendor-image-host-flow", [HEX("a"), null], [HEX("a"), null]);
      const v = deriveProgramIsolation([e]);
      expect(v.holds).to.equal(false);
      // The cross-environment set check would also fire; the receipt must still record the in-environment cause.
      expect(v.violations).to.include("x: withdrawal and ACVP ELFs are identical");
    });

    it("detects a shared vkey inside one environment, and names it as such", function () {
      const e = env("x", "h1", "vendor-image-host-flow", [HEX("a"), `0x${HEX("1")}`], [HEX("b"), `0x${HEX("1")}`]);
      const v = deriveProgramIsolation([e]);
      expect(v.holds).to.equal(false);
      expect(v.violations).to.include("x: withdrawal and ACVP vkeys are identical");
    });

    it("detects an ACVP identity used as a withdrawal identity elsewhere", function () {
      const x = env("x", "h1", "vendor-image-host-flow", [HEX("a"), `0x${HEX("1")}`], [HEX("b"), `0x${HEX("2")}`]);
      const y = env("y", "h2", "vendor-image-host-flow", [HEX("c"), `0x${HEX("2")}`], [HEX("d"), `0x${HEX("4")}`]);
      expect(deriveProgramIsolation([x, y]).violations.join(" ")).to.match(
        /withdrawal vkey in one environment and an ACVP vkey/,
      );
    });
  });

  describe("gateway derivation", function () {
    const gw = (): VerifierGatewayObservations => clone(INPUTS.gateway);
    const target = "test";

    it("classifies the measured owners (mainnet Safe 2-of-3, Sepolia single EOA)", function () {
      const v = deriveGatewayVerdict(gw(), target);
      const byChain = Object.fromEntries(v.chains.map((c) => [c.chainId, c]));
      expect(byChain["1"].ownerKind).to.match(/^Safe 1\.3\.0 2-of-3 \(modules: 0, guard: none\)$/);
      expect(byChain["11155111"].ownerKind).to.equal("EOA (single key)");
      expect(byChain["1"].liveRoutes.map((r) => r.version)).to.deep.equal(["v6.1.0"]);
      expect(byChain["11155111"].liveRoutes.map((r) => r.version).sort()).to.deep.equal(["v4.0.0-rc.3", "v6.1.0"]);
      expect(v.chains.every((c) => c.routeEnumerationAgrees && !c.proxySlotsSet)).to.equal(true);
    });

    it("an owner keeps provenance NOT_ESTABLISHED even with every byte attributed", function () {
      const v = deriveGatewayVerdict(gw(), target);
      expect(v.bytesAttributed).to.deep.equal({ gateway: true, sp1VerifierGroth16V610: true, vkConstantsJoined: true });
      expect(v.ownerMutable).to.equal(true);
      expect(v.status).to.equal("NOT_ESTABLISHED");
    });

    it("an ownerless, non-proxy, attributed gateway would be ESTABLISHED (positive control: the rule is not vacuous)", function () {
      const o = gw();
      for (const c of Object.values(o.chains)) {
        c.groth16Gateway.owner = "0x0000000000000000000000000000000000000000";
        c.groth16Gateway.ownerCodeBytes = 0;
      }
      expect(deriveGatewayVerdict(o, target).status).to.equal("ESTABLISHED");
    });

    it("the committed state reads are corroborated by a second RPC provider", function () {
      expect(committed().verifierGateway.stateReadsCorroborated).to.equal(true);
    });

    it("an ownerless gateway without second-provider corroboration is not ESTABLISHED", function () {
      const ownerless = () => {
        const o = gw();
        for (const c of Object.values(o.chains)) {
          c.groth16Gateway.owner = "0x0000000000000000000000000000000000000000";
          c.groth16Gateway.ownerCodeBytes = 0;
        }
        return o;
      };
      expect(deriveGatewayVerdict(ownerless(), target).status, "positive control").to.equal("ESTABLISHED");
      const missing = ownerless();
      delete missing.secondProvider;
      expect(deriveGatewayVerdict(missing, target).status).to.equal("NOT_ESTABLISHED");
      const partial = ownerless();
      partial.secondProvider!.checks = partial.secondProvider!.checks.slice(0, 1);
      expect(deriveGatewayVerdict(partial, target).status).to.equal("NOT_ESTABLISHED");
      const disagree = ownerless();
      disagree.secondProvider!.checks[0].routesSame = false;
      expect(deriveGatewayVerdict(disagree, target).stateReadsCorroborated).to.equal(false);
    });

    it("a set EIP-1967 slot makes an ownerless gateway mutable", function () {
      const o = gw();
      for (const c of Object.values(o.chains)) c.groth16Gateway.owner = "0x0000000000000000000000000000000000000000";
      o.chains["1"].groth16Gateway.eip1967ImplementationSlot = `0x${"0".repeat(63)}1`;
      expect(deriveGatewayVerdict(o, target).status).to.equal("NOT_ESTABLISHED");
    });

    it("a route the logs and the probes disagree on blocks an ownerless gateway", function () {
      const o = gw();
      for (const c of Object.values(o.chains)) c.groth16Gateway.owner = "0x0000000000000000000000000000000000000000";
      o.chains["1"].groth16Gateway.routes.pop();
      expect(deriveGatewayVerdict(o, target).status).to.equal("NOT_ESTABLISHED");
    });

    it("the VK join requires the decoded key's sha256 to equal VERIFIER_HASH", function () {
      const o = gw();
      o.attribution.vkConstantJoin.vkSha256 = `0x${HEX("e")}`;
      expect(deriveGatewayVerdict(o, target).bytesAttributed.vkConstantsJoined).to.equal(false);
      const p = gw();
      p.attribution.vkConstantJoin.mismatches = 1;
      expect(deriveGatewayVerdict(p, target).bytesAttributed.vkConstantsJoined).to.equal(false);
    });

    it("a missing CREATE2 join or Sourcify match un-attributes the verifier bytes", function () {
      const o = gw();
      o.attribution.sp1VerifierGroth16V610.create2.equalsAddress = false;
      expect(deriveGatewayVerdict(o, target).bytesAttributed.sp1VerifierGroth16V610).to.equal(false);
      const p = gw();
      p.sourcify = p.sourcify.filter((s) => s.address.toLowerCase() !== "0xb69f2584cbcff99a58c4e7002e8b89af54a6f4e2");
      expect(deriveGatewayVerdict(p, target).bytesAttributed.sp1VerifierGroth16V610).to.equal(false);
    });
  });
});
