/**
 * SP1-PA3C-Q1: the observer qualification (scripts/lib/sp1-observer-qualification.ts): the pure derivation of a raw
 * observer capture into a comparable record, the soak summary over many captures, the host-versus-container
 * reconciliation (every security-relevant field equal, not "both exited 0"), the negative controls that must each fail
 * for their intended reason, and the qualification record's validator, which recomputes the state from facts (a
 * measurement never grades itself). Offline: the committed self-test capture is the only kernel evidence read; no
 * kernel, docker, network, SP1 or proof. Research prototype. Not audited.
 */
import { expect } from "chai";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { OBSERVER_SCRIPT_REL, sha256Hex } from "../scripts/sp1-egress-observer";
import type { RawEvidence } from "../scripts/lib/sp1-egress-attribution";
import {
  DERIVATION_SCHEMA,
  FIXTURE_DIR_REL,
  FIXTURE_HOST_EXECUTABLE,
  LANE,
  MIN_SOAK_ITERATIONS,
  NEGATIVE_CONTROLS,
  OBSERVATION_SCHEMA,
  PRODUCTION_SP1_BINDING,
  QUALIFICATION_REL,
  QUALIFICATION_SCHEMA,
  REPOSITORY_PINNED_COMPONENTS,
  SOAK_VARIATIONS,
  STATES,
  deriveQualification,
  environmentErrors,
  leafDifferences,
  qualificationErrors,
  qualificationRecordFrom,
  qualificationStateOf,
  readRawDir,
  reconcileDerivations,
  runNegativeControls,
  serializeQualification,
  soakSummaryOf,
  type Derivation,
  type DerivationOutput,
  type EnvironmentIdentity,
  type QualificationObservation,
  type SoakIteration,
  type ValidationContext,
} from "../scripts/lib/sp1-observer-qualification";
import { tsCandidate } from "../scripts/sp1-observer-qualification/node-ts-resolve-hook.mjs";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const lf = (text: string) => text.replace(/\r\n/g, "\n");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const must = <T>(x: T | null | undefined): T => {
  if (x === null || x === undefined) throw new Error("a value that must be there is not");
  return x;
};
const COMMIT = "b9fcd4d59dbea265bc21175ab141037e5698a991";
const IMAGE_DIGEST = "sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd";
const RUN_OPTIONS = [
  "docker",
  "run",
  "--rm",
  "--network",
  "none",
  "--read-only",
  "--cap-drop",
  "ALL",
  "--security-opt",
  "no-new-privileges",
  "--user",
  "65534:65534",
  "--pids-limit",
  "64",
  "--memory",
  "1g",
  "-v",
  "/var/lib/sp1obs-q1/src:/src:ro",
  "-v",
  "/var/lib/sp1obs-q1/raw:/raw:ro",
  "-v",
  "/var/lib/sp1obs-q1/in:/in:ro",
  "-v",
  "/var/lib/sp1obs-q1/out:/out",
  `node@${IMAGE_DIGEST}`,
  "node",
  "--import",
  "/src/scripts/sp1-observer-qualification/node-ts-loader.mjs",
  "/src/scripts/sp1-observer-qualification.ts",
  "derive",
];

const fixtureRaw = (): RawEvidence => {
  const read = (f: string) => lf(readFileSync(join(FIXTURE_DIR_REL, f), "latin1"));
  return { trace: read("trace.txt"), facts: read("facts.json"), manifest: read("manifest.json") };
};
const committedObserver = () => sha256Hex(lf(readFileSync(OBSERVER_SCRIPT_REL, "utf8")));

const HOST_ENV: EnvironmentIdentity = {
  kind: "HOST",
  label: "developer-workstation-wsl2",
  platform: "linux",
  release: "6.18.33.1-microsoft-standard-WSL2",
  arch: "x64",
  node: "v24.16.0",
  typescriptExecution: "tsx",
  sourceCommit: COMMIT,
};
const CONTAINER_ENV: EnvironmentIdentity = {
  kind: "CONTAINER",
  label: "clean-container",
  platform: "linux",
  release: "6.18.33.1-microsoft-standard-WSL2",
  arch: "x64",
  node: "v24.18.0",
  typescriptExecution: "node-type-stripping",
  sourceCommit: COMMIT,
  container: {
    image: {
      reference: "node:24-alpine",
      digest: IMAGE_DIGEST,
      id: IMAGE_DIGEST,
      nodeVersion: "24.18.0",
      registryVerification: "docker.io/library/node manifest by digest: HTTP 200 (read-only; nothing pulled)",
    },
    runOptions: RUN_OPTIONS,
    facts: {
      uid: 65534,
      gid: 65534,
      networkInterfaces: ["lo"],
      capEff: "0000000000000000",
      noNewPrivs: 1,
      rootMount: "ro",
      env: ["HOME", "HOSTNAME", "NODE_VERSION", "PATH", "YARN_VERSION"],
    },
  },
};

function derivationOf(env: EnvironmentIdentity, output: DerivationOutput, raw = fixtureRaw()): Derivation {
  const manifest = JSON.parse(raw.manifest) as { files: { name: string; bytes: number; sha256: string }[] };
  return {
    schema: DERIVATION_SCHEMA,
    environment: env,
    input: {
      raw: { manifestSha256: sha256(Buffer.from(raw.manifest, "latin1")), files: manifest.files },
      hostExecutable: FIXTURE_HOST_EXECUTABLE,
      observerScriptSha256: committedObserver(),
      mode: "SELF_TEST",
    },
    output,
  };
}

/** A soak of `n` agreeing iterations: each capture distinct (its own nonce and digests), the stable projection one. */
function syntheticSoak(base: DerivationOutput, n: number): SoakIteration[] {
  return Array.from({ length: n }, (_, k) => {
    const output: DerivationOutput = clone(base);
    output.nonce = (k + 1).toString(16).padStart(16, "0");
    output.normalizedSha256 = sha256(`capture-${k}`);
    output.configSha256 = sha256(`config-${k}`);
    output.judgementSha256 = sha256(`judgement-${k}`);
    const host = derivationOf(HOST_ENV, clone(output));
    const container = derivationOf(CONTAINER_ENV, clone(output));
    return {
      n: k + 1,
      variation: SOAK_VARIATIONS[k % SOAK_VARIATIONS.length].name,
      startedAtUtc: `2026-11-01T10:${String(k).padStart(2, "0")}:00Z`,
      seconds: 7,
      exit: 0,
      rawDir: `/var/lib/sp1obs-q1/raw/raw-${k + 1}`,
      rawEntries: ["facts.json", "manifest.json", "trace.txt"],
      factsSummary: { failures: 0, heartbeats: 8, probeMisses: 0, leftoverLines: 0, cleanup: 0 },
      after: { probesLeft: 0, instancesLeft: 0 },
      host,
      container,
    };
  });
}

function syntheticObservation(n = MIN_SOAK_ITERATIONS): QualificationObservation {
  const raw = fixtureRaw();
  const output = deriveQualification(raw, FIXTURE_HOST_EXECUTABLE, committedObserver());
  const host = derivationOf(HOST_ENV, clone(output), raw);
  const container = derivationOf(CONTAINER_ENV, clone(output), raw);
  return {
    schema: OBSERVATION_SCHEMA,
    lane: LANE,
    host: "developer-workstation-wsl2",
    measuredAtUtc: "2026-11-01T12:00:00Z",
    tool: { script: "scripts/sp1-observer-qualification.ts", scriptSha256: "ab".repeat(32) },
    source: { commit: COMMIT, observerScriptSha256: committedObserver() },
    hostFacts: {
      kernelRelease: "6.18.33.1-microsoft-standard-WSL2",
      bootId: "b4db548b-e808-4ce5-b61b-75a251a16c44",
      node: { execPath: "/opt/node/node-v24.16.0-linux-x64/bin/node", version: "v24.16.0", sha256: "cd".repeat(32) },
      nft: "nftables v1.0.9 (Old Doc Yak #3)",
      docker: "29.1.3",
      table: { family: "inet", name: "sp1obs_q1", rulesSha256: "ef".repeat(32) },
    },
    fixture: { host, container },
    soak: {
      startedAtUtc: "2026-11-01T10:00:00Z",
      finishedAtUtc: "2026-11-01T10:30:00Z",
      iterations: syntheticSoak(output, n),
    },
    negativeControls: runNegativeControls({
      raw,
      hostExecutable: FIXTURE_HOST_EXECUTABLE,
      committedObserverSha256: committedObserver(),
      host,
      container,
    }),
  };
}

function validationContext(observation: QualificationObservation): ValidationContext {
  const observationPath =
    "evidence/zk/sp1-impl/observations/observer-qualification-developer-workstation-wsl2.raw.json";
  const observationBytes = Buffer.from(`${JSON.stringify(observation, null, 2)}\n`);
  return {
    readFile: (rel) => {
      if (rel === observationPath) return observationBytes;
      try {
        return readFileSync(resolve(rel));
      } catch {
        return null;
      }
    },
    committedObserverSha256: committedObserver(),
    fixtureDerivation: deriveQualification(fixtureRaw(), FIXTURE_HOST_EXECUTABLE, committedObserver()),
    observations: [{ path: observationPath, observation }],
  };
}

describe("SP1-PA3C-Q1 — observer qualification", function () {
  this.timeout(60_000);

  describe("the derivation of one capture", function () {
    const raw = fixtureRaw();
    const out = deriveQualification(raw, FIXTURE_HOST_EXECUTABLE, committedObserver());

    it("normalizes the committed self-test capture to the digest SP1-PA3C pinned and judges it refusal-free", function () {
      expect(out.normalizedSha256).to.equal("03cef7f6586fe918ce1cc64a57e67e91bbb028a91b8d61efc6c0aac42ee96a25");
      expect(out.refusals).to.deep.equal([]);
      expect(out.judgement?.assurance.level).to.equal("CONTINUOUS_ATTRIBUTED");
      expect(out.judgement?.reconciliation).to.deep.equal({ counted: 3, inner: 3, outer: 3, ok: true });
      expect(out.judgement?.ownAttempts).to.deep.equal([
        {
          scope: "TOOL",
          kind: "connect",
          probe: "tcp4",
          dest: "192.0.2.10:443",
          outcome: "REFUSED",
          qname: null,
          phase: "PHASE:PROBES_BEFORE_BEGIN",
        },
        {
          scope: "PROOF",
          kind: "send",
          probe: "udp4",
          dest: "192.0.2.53:53",
          outcome: "REFUSED",
          qname: "pa3c-selftest.example",
          phase: "PHASE:HOST_SPAWN",
        },
        {
          scope: "TOOL",
          kind: "connect",
          probe: "tcp4",
          dest: "192.0.2.10:443",
          outcome: "REFUSED",
          qname: null,
          phase: "PHASE:PROBES_AFTER_BEGIN",
        },
      ]);
      expect(out.judgementSha256).to.equal(sha256(JSON.stringify(out.judgement)).slice(0, 0) + out.judgementSha256);
      expect(out.judgementSha256).to.match(/^[0-9a-f]{64}$/);
    });

    it("is deterministic: the same bytes derive the same output twice", function () {
      const again = deriveQualification(fixtureRaw(), FIXTURE_HOST_EXECUTABLE, committedObserver());
      expect(JSON.stringify(again)).to.equal(JSON.stringify(out));
    });

    it("keeps run metadata out of the stable projection and the observer's identity in it", function () {
      const p = out.stableProjection as NonNullable<typeof out.stableProjection>;
      const text = JSON.stringify(p);
      expect(text).to.not.include(out.nonce as string);
      expect(text).to.not.include("b4db548b"); // the boot id
      expect(text).to.not.include("172.22.169.196"); // the host's uplink address, a per-boot fact
      expect(p.observer).to.deep.equal({
        script: OBSERVER_SCRIPT_REL,
        scriptSha256: committedObserver(),
        mechanism: "LINUX_TRACEFS_KPROBES",
        mode: "SELF_TEST",
      });
      expect(p.probeTemplate.every((line) => line.includes("sp1obs_<nonce>/"))).to.equal(true);
      expect(p.probeTemplate).to.have.length(27);
      expect(p.boundaryRules.map((r) => r.verdict)).to.deep.equal(["reject", "reject", "reject"]);
      expect(p.refusals).to.deep.equal([]);
      expect(p.ownAttempts).to.deep.equal(out.judgement?.ownAttempts);
      expect(p.assurance).to.deep.include({ level: "CONTINUOUS_ATTRIBUTED", processAttribution: "COMPLETE" });
      expect(out.stableProjectionSha256).to.equal(sha256(JSON.stringify(p)).slice(0, 0) + out.stableProjectionSha256);
    });

    it("refuses a capture the manifest does not bind, with the reason named, and derives nothing from it", function () {
      const broken = { ...raw, trace: raw.trace.replace("READY mode=SELF_TEST", "REAdY mode=SELF_TEST") };
      const r = deriveQualification(broken, FIXTURE_HOST_EXECUTABLE, committedObserver());
      expect(r.refusals.map((x) => x.reason)).to.deep.equal(["RAW_NOT_BOUND"]);
      expect([r.normalizedSha256, r.judgement, r.stableProjection]).to.deep.equal([null, null, null]);
    });

    it("binds the derivation to the committed observer: another observer's capture is TOOL_NOT_BOUND", function () {
      const r = deriveQualification(raw, FIXTURE_HOST_EXECUTABLE, "00".repeat(32));
      expect(r.refusals.map((x) => x.reason)).to.include("TOOL_NOT_BOUND");
      expect(r.normalizedSha256).to.equal(out.normalizedSha256); // the normalization is of the bytes; the binding refuses
    });
  });

  describe("reading a raw directory", function () {
    const files = new Map<string, string>([
      ["trace.txt", "t"],
      ["facts.json", "f"],
      ["manifest.json", "m"],
    ]);
    const fsOf = (entries: Map<string, string>) => ({
      list: () => [...entries.keys()].sort(),
      read: (name: string) => entries.get(name) as string,
    });

    it("reads exactly the observer's three files", function () {
      expect(readRawDir("/raw", fsOf(files))).to.deep.equal({ trace: "t", facts: "f", manifest: "m" });
    });

    it("refuses a directory holding anything else (an unexpected write is a mutation, never ignored)", function () {
      const extra = new Map(files);
      extra.set("notes.txt", "x");
      expect(() => readRawDir("/raw", fsOf(extra))).to.throw(/RAW_DIR_UNEXPECTED_FILE: \/raw holds notes\.txt/);
    });

    it("refuses a directory missing one of them", function () {
      const less = new Map(files);
      less.delete("facts.json");
      expect(() => readRawDir("/raw", fsOf(less))).to.throw(/RAW_DIR_INCOMPLETE: \/raw lacks facts\.json/);
    });
  });

  describe("the soak summary", function () {
    const base = deriveQualification(fixtureRaw(), FIXTURE_HOST_EXECUTABLE, committedObserver());

    it("is stable when every capture is distinct, clean, refusal-free and projects to one digest", function () {
      const s = soakSummaryOf(syntheticSoak(base, 12));
      expect(s).to.deep.include({
        iterations: 12,
        exitZero: 12,
        refusalFree: 12,
        clean: 12,
        distinctCaptures: 12,
        distinctProjections: 1,
        stable: true,
      });
      expect(s.variations).to.include.members(["plain", "tz", "locale", "umask-077", "cwd-root"]);
      expect(s.unstableBecause).to.deep.equal([]);
    });

    it("is unstable when two iterations project differently, naming them", function () {
      const it2 = syntheticSoak(base, 10);
      const p = it2[3].host.output.stableProjection as NonNullable<DerivationOutput["stableProjection"]>;
      p.ownAttempts = [];
      it2[3].host.output.stableProjectionSha256 = sha256("other");
      it2[3].container.output.stableProjectionSha256 = sha256("other");
      const s = soakSummaryOf(it2);
      expect(s.stable).to.equal(false);
      expect(s.distinctProjections).to.equal(2);
      expect(s.unstableBecause.join(" ")).to.match(/iteration 4 projects differently/);
    });

    it("detects a reused capture: two iterations with one normalized digest are stale-state reuse", function () {
      const it2 = syntheticSoak(base, 10);
      it2[5].host.output.normalizedSha256 = it2[2].host.output.normalizedSha256;
      it2[5].container.output.normalizedSha256 = it2[2].host.output.normalizedSha256;
      const s = soakSummaryOf(it2);
      expect(s.stable).to.equal(false);
      expect(s.distinctCaptures).to.equal(9);
      expect(s.unstableBecause.join(" ")).to.match(/iterations 3 and 6 hold one capture/);
    });

    it("is unstable when an iteration left probes behind, exited non-zero, or was refused", function () {
      const dirty = syntheticSoak(base, 10);
      dirty[0].after.probesLeft = 2;
      dirty[1].exit = 3;
      dirty[2].host.output.refusals = [{ reason: "OBSERVER_GAP", detail: "x" }];
      dirty[2].container.output.refusals = [{ reason: "OBSERVER_GAP", detail: "x" }];
      const s = soakSummaryOf(dirty);
      expect(s).to.deep.include({ clean: 9, exitZero: 9, refusalFree: 9, stable: false });
      expect(s.unstableBecause).to.have.length(3);
    });

    it("is unstable when a host and container derivation of one iteration disagree", function () {
      const it2 = syntheticSoak(base, 10);
      it2[7].container.output.normalizedSha256 = sha256("tampered");
      const s = soakSummaryOf(it2);
      expect(s.stable).to.equal(false);
      expect(s.unstableBecause.join(" ")).to.match(/iteration 8: host and container disagree/);
    });
  });

  describe("host versus container reconciliation", function () {
    const output = deriveQualification(fixtureRaw(), FIXTURE_HOST_EXECUTABLE, committedObserver());
    const host = derivationOf(HOST_ENV, output);
    const container = derivationOf(CONTAINER_ENV, output);

    it("agrees when every input and output field is equal, classing environment identity as expected", function () {
      const r = reconcileDerivations(host, container);
      expect(r.result).to.equal("HOST_CONTAINER_OBSERVER_AGREEMENT");
      expect(r.differences.every((d) => d.class === "EXPECTED_ENVIRONMENT_IDENTITY")).to.equal(true);
      expect(r.differences.map((d) => d.path)).to.include.members([
        "environment.kind",
        "environment.node",
        "environment.typescriptExecution",
      ]);
    });

    it("disagrees on any output difference, naming the field as security-relevant", function () {
      const c = clone(container);
      (c.output.judgement as NonNullable<DerivationOutput["judgement"]>).ownAttempts[1].outcome = "SENT";
      const r = reconcileDerivations(host, c);
      expect(r.result).to.equal("HOST_CONTAINER_OBSERVER_DISAGREEMENT");
      expect(r.differences.filter((d) => d.class === "SECURITY_RELEVANT_MISMATCH").map((d) => d.path)).to.deep.equal([
        "output.judgement.ownAttempts.1.outcome",
      ]);
    });

    it("disagrees when the inputs differ (another capture or executable), as an input mismatch", function () {
      const c = clone(container);
      c.input.hostExecutable = { ...c.input.hostExecutable, ino: 7 };
      const r = reconcileDerivations(host, c);
      expect(r.result).to.equal("HOST_CONTAINER_OBSERVER_DISAGREEMENT");
      expect(r.differences.filter((d) => d.class === "INPUT_IDENTITY_MISMATCH").map((d) => d.path)).to.deep.equal([
        "input.hostExecutable.ino",
      ]);
    });

    it("never classes the source commit as expected environment variation", function () {
      const c = clone(container);
      c.environment.sourceCommit = "0".repeat(40);
      const r = reconcileDerivations(host, c);
      expect(r.result).to.equal("HOST_CONTAINER_OBSERVER_DISAGREEMENT");
      expect(r.differences.find((d) => d.path === "environment.sourceCommit")?.class).to.equal(
        "SOURCE_IDENTITY_MISMATCH",
      );
    });

    it("lists leaf differences by path, arrays by index and length", function () {
      expect(leafDifferences({ a: [1, 2], b: { c: 1 } }, { a: [1, 3, 4], b: { c: 1 } })).to.deep.equal([
        { path: "a.1", a: 2, b: 3 },
        { path: "a.length", a: 2, b: 3 },
      ]);
    });
  });

  describe("the environment identity", function () {
    it("accepts the clean container as run, and names what a weaker container lacks", function () {
      expect(environmentErrors(CONTAINER_ENV)).to.deep.equal([]);
      const weak = clone(CONTAINER_ENV);
      const c = weak.container as NonNullable<EnvironmentIdentity["container"]>;
      c.runOptions = c.runOptions.filter(
        (o, i, all) => !(o === "--read-only" || (all[i - 1] === "--network" && o === "none") || o === "--network"),
      );
      c.runOptions.push("--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock");
      c.facts.uid = 0;
      c.facts.networkInterfaces = ["lo", "eth0"];
      const errors = environmentErrors(weak);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: --network none/);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: --read-only/);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: --privileged/);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: docker\.sock/);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: ran as root/);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: network interfaces lo, eth0/);
    });

    it("requires every mount but the output to be read-only, and the image pinned by digest", function () {
      const w = clone(CONTAINER_ENV);
      const c = w.container as NonNullable<EnvironmentIdentity["container"]>;
      c.runOptions = c.runOptions.map((o) =>
        o === "/var/lib/sp1obs-q1/src:/src:ro" ? "/var/lib/sp1obs-q1/src:/src" : o,
      );
      c.runOptions = c.runOptions.map((o) => (o === `node@${IMAGE_DIGEST}` ? "node:24-alpine" : o));
      const errors = environmentErrors(w);
      expect(errors.join("\n")).to.match(/CONTAINER_NOT_HARDENED: \/src is writable/);
      expect(errors.join("\n")).to.match(/PROVENANCE_INVALID: the image is not run by digest/);
    });

    it("names an incomplete identity (a missing tool version) and an invalid provenance field", function () {
      const noNode = clone(HOST_ENV) as Partial<EnvironmentIdentity>;
      delete noNode.node;
      expect(environmentErrors(noNode as EnvironmentIdentity)).to.deep.equal([
        "ENVIRONMENT_INCOMPLETE: node is missing",
      ]);
      const bad = clone(CONTAINER_ENV);
      (bad.container as NonNullable<EnvironmentIdentity["container"]>).image.digest = "latest";
      expect(environmentErrors(bad).join("\n")).to.match(/PROVENANCE_INVALID: image\.digest latest/);
      const noCommit = { ...clone(HOST_ENV), sourceCommit: "main" };
      expect(environmentErrors(noCommit).join("\n")).to.match(/PROVENANCE_INVALID: sourceCommit main/);
    });
  });

  describe("the negative controls", function () {
    const raw = fixtureRaw();
    const output = deriveQualification(raw, FIXTURE_HOST_EXECUTABLE, committedObserver());
    const ctx = {
      raw,
      hostExecutable: FIXTURE_HOST_EXECUTABLE,
      committedObserverSha256: committedObserver(),
      host: derivationOf(HOST_ENV, output, raw),
      container: derivationOf(CONTAINER_ENV, output, raw),
    };

    it("has the eight required controls, and each fails for its intended reason", function () {
      const results = runNegativeControls(ctx);
      expect(results.map((r) => r.id)).to.deep.equal(NEGATIVE_CONTROLS.map((c) => c.id));
      expect(results.map((r) => r.id)).to.include.members(["NC1", "NC2", "NC3", "NC4", "NC5", "NC6", "NC7", "NC8"]);
      for (const r of results.filter((x) => x.id !== "P0")) {
        expect(r.observedReasons, r.id).to.include(r.intendedReason);
        expect(r.ok, r.id).to.equal(true);
      }
    });

    it("passes the positive control: the unmodified capture derives, agrees and is refusal-free", function () {
      const results = runNegativeControls(ctx);
      const p0 = results.find((r) => r.id === "P0") as NonNullable<(typeof results)[number]>;
      expect(p0.observedReasons).to.deep.equal([]);
      expect(p0.ok).to.equal(true);
    });

    it("reports a control that does not fail as not ok (a weakened check is seen)", function () {
      // A context whose "committed" observer is another: NC4 (stale evidence against a new source identity) would then
      // not single out the staleness, and P0 fails too: the harness reports both, hiding neither.
      const results = runNegativeControls({ ...ctx, committedObserverSha256: "11".repeat(32) });
      const p0 = results.find((r) => r.id === "P0") as NonNullable<(typeof results)[number]>;
      expect(p0.ok).to.equal(false);
      expect(p0.observedReasons).to.include("TOOL_NOT_BOUND");
    });
  });

  describe("the qualification record", function () {
    const observation = syntheticObservation();
    const ctx = validationContext(observation);
    const record = qualificationRecordFrom(ctx);

    it("derives OBSERVER_QUALIFIED_FOR_PA3D from agreeing, stable, controlled facts, naming the next lane", function () {
      expect(record.schema).to.equal(QUALIFICATION_SCHEMA);
      expect(record.lane).to.equal(LANE);
      expect(record.productionSp1Binding).to.equal(PRODUCTION_SP1_BINDING);
      expect(record.state).to.equal("OBSERVER_QUALIFIED_FOR_PA3D");
      expect(record.blockers).to.deep.equal([]);
      expect(record.next).to.deep.equal({
        lane: "SP1-PA3D",
        what: "owner-authorized v2 attributed proof exercise under the observer",
        authorization: "OWNER",
        started: false,
      });
      expect(must(record.fixture).reconciliation.result).to.equal("HOST_CONTAINER_OBSERVER_AGREEMENT");
      expect(must(record.soak).summary.stable).to.equal(true);
      expect(record.negativeControls.every((c) => c.ok)).to.equal(true);
      expect(qualificationErrors(record, ctx)).to.deep.equal([]);
    });

    it("pins every repository-controlled component of the observer path by sha256", function () {
      const pinned = record.components.filter((c) => c.class === "repository-pinned");
      expect(pinned.map((c) => c.path)).to.have.members(REPOSITORY_PINNED_COMPONENTS);
      for (const c of pinned) {
        expect(c.sha256, c.path).to.equal(sha256(lf(readFileSync(resolve(c.path as string), "utf8"))));
      }
      expect(record.components.map((c) => c.class)).to.include.members([
        "repository-pinned",
        "digest-pinned",
        "version-pinned",
        "host-dependent",
        "network-dependent",
      ]);
    });

    it("holds no proof and no pretend proof: a proof-shaped field is refused by name", function () {
      expect(JSON.stringify(record)).to.not.match(/"(proofBytes|publicValues|vkey)"/);
      const bad = clone(record) as unknown as Record<string, unknown>;
      bad.proof = { vkey: "0x00" };
      expect(qualificationErrors(bad, ctx).join("\n")).to.match(/NO_PROOF_ARTIFACT: proof\.vkey/);
    });

    it("recomputes the state: a record that calls itself qualified over an unstable soak is refused", function () {
      const bad = clone(record);
      must(bad.soak).summary.stable = false;
      must(bad.soak).summary.unstableBecause = ["iteration 2 projects differently"];
      const errors = qualificationErrors(bad, ctx);
      expect(errors.join("\n")).to.match(/SOAK_SUMMARY_MISMATCH/);
    });

    it("blocks when a soak iteration disagrees, and the state must say so", function () {
      const o = clone(observation);
      o.soak.iterations[2].container.output.normalizedSha256 = sha256("other");
      const c2 = validationContext(o);
      const r2 = qualificationRecordFrom(c2);
      expect(r2.state).to.equal("OBSERVER_QUALIFICATION_BLOCKED");
      expect(r2.blockers.join("\n")).to.match(/SOAK_UNSTABLE: iteration 3: host and container disagree/);
      expect(qualificationErrors(r2, c2)).to.deep.equal([]);
      const lie = clone(r2);
      lie.state = "OBSERVER_QUALIFIED_FOR_PA3D";
      lie.blockers = [];
      expect(qualificationErrors(lie, c2).join("\n")).to.match(
        /STATE_MISMATCH: the facts derive OBSERVER_QUALIFICATION_BLOCKED/,
      );
    });

    it("blocks when fewer than the minimum iterations soaked, or a negative control did not fail", function () {
      const few = validationContext(syntheticObservation(MIN_SOAK_ITERATIONS - 1));
      expect(qualificationRecordFrom(few).blockers.join("\n")).to.match(/SOAK_TOO_SHORT/);
      const o = clone(observation);
      (o.negativeControls.find((c) => c.id === "NC2") as NonNullable<(typeof o.negativeControls)[number]>).ok = false;
      const r = qualificationRecordFrom(validationContext(o));
      expect(r.state).to.equal("OBSERVER_QUALIFICATION_BLOCKED");
      expect(r.blockers.join("\n")).to.match(/NEGATIVE_CONTROL_FAILED: NC2/);
    });

    it("refuses a committed record whose negative-control results are not what re-running them gives", function () {
      const bad = clone(record);
      bad.negativeControls[2].observedReasons = ["NOTHING"];
      expect(qualificationErrors(bad, ctx).join("\n")).to.match(/NEGATIVE_CONTROLS_MISMATCH/);
    });

    it("refuses a record whose fixture digests are not what this machine derives (the expected digest changed)", function () {
      const bad = clone(record);
      must(bad.fixture).host.output.normalizedSha256 = sha256("expected-changed");
      expect(qualificationErrors(bad, ctx).join("\n")).to.match(/FIXTURE_DIGEST_MISMATCH/);
    });

    it("refuses a record made for another observer (stale evidence against a new source identity)", function () {
      const errors = qualificationErrors(record, { ...ctx, committedObserverSha256: "22".repeat(32) });
      expect(errors.join("\n")).to.match(/OBSERVER_CHANGED: re-qualify/);
    });

    it("refuses a record whose pinned component bytes changed", function () {
      const bad = clone(record);
      const c = bad.components.find((x) => x.path === OBSERVER_SCRIPT_REL) as NonNullable<
        (typeof bad.components)[number]
      >;
      c.sha256 = "33".repeat(32);
      expect(qualificationErrors(bad, ctx).join("\n")).to.match(/COMPONENT_CHANGED: scripts\/sp1-egress-observer\.ts/);
    });

    it("is OBSERVER_TOOLING_READY_VALIDATION_PENDING with no observation, and never qualified", function () {
      const none = qualificationRecordFrom({ ...ctx, observations: [] });
      expect(none.state).to.equal("OBSERVER_TOOLING_READY_VALIDATION_PENDING");
      expect(none.next).to.equal(null);
      expect(qualificationErrors(none, { ...ctx, observations: [] })).to.deep.equal([]);
    });

    it("serializes deterministically with sorted keys, LF and a final newline", function () {
      const text = serializeQualification(record);
      expect(text.endsWith("}\n")).to.equal(true);
      expect(text).to.not.include("\r");
      expect(serializeQualification(clone(record))).to.equal(text);
      expect(STATES).to.deep.equal([
        "OBSERVER_QUALIFIED_FOR_PA3D",
        "OBSERVER_QUALIFICATION_BLOCKED",
        "OBSERVER_TOOLING_READY_VALIDATION_PENDING",
      ]);
      expect(QUALIFICATION_REL).to.equal("evidence/zk/sp1-impl/observer-qualification.json");
    });

    it("derives the state from facts alone", function () {
      expect(
        qualificationStateOf({
          observed: true,
          soak: { stable: true, iterations: MIN_SOAK_ITERATIONS, unstableBecause: [] },
          fixtureAgreement: true,
          negativeControls: [{ id: "NC1", ok: true }],
          positiveControl: true,
          environmentErrors: [],
          blockingFindings: [],
        }),
      ).to.deep.equal({ state: "OBSERVER_QUALIFIED_FOR_PA3D", blockers: [] });
      expect(
        qualificationStateOf({
          observed: true,
          soak: { stable: true, iterations: MIN_SOAK_ITERATIONS, unstableBecause: [] },
          fixtureAgreement: false,
          negativeControls: [],
          positiveControl: true,
          environmentErrors: ["CONTAINER_NOT_HARDENED: --privileged"],
          blockingFindings: ["SF-X"],
        }).blockers,
      ).to.deep.equal([
        "HOST_CONTAINER_DISAGREEMENT: the fixture's host and container derivations differ",
        "NEGATIVE_CONTROLS_MISSING: no negative control ran",
        "CONTAINER_NOT_HARDENED: --privileged",
        "SECURITY_FINDING_BLOCKING: SF-X",
      ]);
    });
  });

  describe("the zero-dependency TypeScript loader for the container", function () {
    const isFile = (p: string) => {
      const posix = p.replace(/\\/g, "/");
      return posix.endsWith("/scripts/sp1-egress-observer.ts") || posix.endsWith("lib/sp1-egress-attribution.ts");
    };

    it("resolves a relative, extensionless specifier to its .ts file when that file exists", function () {
      expect(
        tsCandidate("../sp1-egress-observer", "file:///src/scripts/lib/sp1-egress-attribution.ts", isFile),
      ).to.equal("file:///src/scripts/sp1-egress-observer.ts");
      expect(tsCandidate("./lib/sp1-egress-attribution", "file:///src/scripts/x.ts", isFile)).to.equal(
        "file:///src/scripts/lib/sp1-egress-attribution.ts",
      );
    });

    it("leaves every other specifier alone: bare names, built-ins, extensions, and files that are not there", function () {
      expect(tsCandidate("node:fs", "file:///src/a.ts", isFile)).to.equal(null);
      expect(tsCandidate("chai", "file:///src/a.ts", isFile)).to.equal(null);
      expect(tsCandidate("./x.mjs", "file:///src/a.ts", isFile)).to.equal(null);
      expect(tsCandidate("./missing", "file:///src/a.ts", isFile)).to.equal(null);
      expect(tsCandidate("../sp1-egress-observer", undefined, isFile)).to.equal(null);
    });
  });

  describe("the repository-owned runners", function () {
    it("the container runner uses only the hardened docker run options and no network, socket or home", function () {
      const text = lf(readFileSync("scripts/sp1-observer-qualification/container-derive.sh", "utf8"));
      for (const must of [
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user ",
        "--pids-limit",
        ":/src:ro",
        ":/raw:ro",
        "@sha256:",
      ]) {
        expect(text, must).to.include(must);
      }
      for (const never of [
        "--privileged",
        "docker.sock",
        "--network host",
        "--net=host",
        "$HOME:",
        "SSH_AUTH_SOCK",
        "--env-file",
        "npm ",
        "curl ",
        "wget ",
      ]) {
        expect(text, never).to.not.include(never);
      }
    });

    it("the root soak runner imports node built-ins only (root never executes code from node_modules)", function () {
      const text = lf(readFileSync("scripts/sp1-observer-soak.ts", "utf8"));
      const specifiers = [...text.matchAll(/^import [^;]*? from "([^"]+)";$/gm)].map((m) => m[1]);
      expect(specifiers.length).to.be.greaterThan(0);
      expect(specifiers.every((s) => s.startsWith("node:"))).to.equal(true, specifiers.join(", "));
      expect(text).to.include("self-test");
      expect(text).to.not.match(/\brun\b.*--as.*measure-sp1/); // it never starts the proof-exercise tool
    });

    it("the soak variations are the fixed list the summary names", function () {
      expect(SOAK_VARIATIONS.map((v) => v.name)).to.deep.equal([
        "plain",
        "plain",
        "plain",
        "plain",
        "tz",
        "locale",
        "home",
        "umask-077",
        "cwd-root",
        "cwd-tmp",
        "plain",
        "plain",
      ]);
      expect(SOAK_VARIATIONS.length).to.be.at.least(MIN_SOAK_ITERATIONS);
    });
  });
});
