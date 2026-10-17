/**
 * SP1-PA2A: the archive-only prove gate (scripts/lib/sp1-prove-gate.ts).
 *
 * The pinned prover downloads the circuit whenever $SP1_GROTH16_CIRCUIT_PATH/v6.1.0 is absent and pulls its gnark image
 * by a mutable tag. These tests prove the gate never starts the host when the record, the installation, its integrity
 * or the local digest-pinned image is missing, never inherits a security-bearing variable, and refuses hostile
 * environments outright. The host is a stub spawner (and, once, a real child process that prints its environment);
 * no test needs docker, the network, SP1 or a real circuit.
 */
import { expect } from "chai";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join, sep } from "node:path";

import { CircuitToolingError } from "../scripts/lib/sp1-circuit-archive";

import { SAFE_FILES, SYNTHETIC_ANCHOR, gz, safeTar, syntheticRecord } from "../scripts/lib/sp1-circuit-fixtures";
import { installCircuitArchive } from "../scripts/lib/sp1-circuit-install";
import {
  DOCKER_CONTEXT_FROZEN,
  FROZEN_ENV,
  LOCAL_PROVER,
  PASS_THROUGH_ENV,
  REFUSED_ENV,
  buildProverEnv,
  circuitRootError,
  prepareArchiveOnlyProve,
  proofOutput,
  runArchiveOnlyProve,
  spawnHost,
  posixRootGuard,
  posixRootGuardFor,
  securePathError,
  type LocalImageDigests,
  type RootGuard,
  type ProveGateInput,
  type ProvePlan,
  type SpawnResult,
} from "../scripts/lib/sp1-prove-gate";
import { refusalOf, tempDirs } from "./helpers/circuit-tooling";

const anchor = SYNTHETIC_ANCHOR;
const archive = gz(safeTar());
const record = syntheticRecord(archive, SAFE_FILES);
const imageRef = `${record.gnark.repository}@${record.gnark.digest}`;
const otherDigest = `${record.gnark.repository}@sha256:${"b".repeat(64)}`;
const present: LocalImageDigests = (ref) => (ref === imageRef ? [imageRef] : null);
const selector = anchor.verifyingKey.sha256.slice(2, 10);
const okOutput = JSON.stringify({ vkey: anchor.programVKey, publicValues: "0x00ff", proofBytes: `0x${selector}abcd` });
/** A guard that locks nothing, so the stub-spawner tests run on every platform; posixRootGuard has its own tests. */
const guardLog: string[] = [];
const openGuard: RootGuard = (root, dir) => {
  guardLog.push(`lock ${root} ${dir}`);
  return { release: () => void guardLog.push("release") };
};

describe("SP1-PA2A archive-only prove gate", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());

  async function world() {
    const work = dirs.make();
    const archivePath = join(work, "a.tar.gz");
    writeFileSync(archivePath, archive);
    const root = join(work, "circuits");
    mkdirSync(root);
    const installed = await installCircuitArchive({ archivePath, record, anchor, destinationRoot: root });
    const host = join(work, "mldsa65-host");
    const inputs = join(work, "inputs.json");
    writeFileSync(host, "stub");
    writeFileSync(inputs, "{}");
    const input = (over: Partial<ProveGateInput> = {}): ProveGateInput => ({
      record,
      anchor,
      circuitRoot: root,
      hostExecutable: host,
      inputsPath: inputs,
      callerEnv: { PATH: "/usr/bin" },
      ...over,
    });
    return { work, root, circuitDir: installed.circuitDir, host, inputs, input };
  }

  /** A spawner that records every call; the gate must call it at most once, and never after a refusal. */
  function spy(result: Partial<SpawnResult> | ((plan: ProvePlan) => Promise<SpawnResult>) = {}) {
    const calls: ProvePlan[] = [];
    const spawn = async (plan: ProvePlan): Promise<SpawnResult> => {
      calls.push(plan);
      if (typeof result === "function") return result(plan);
      return { status: 0, signal: null, stdout: `log line\n${okOutput}\n`, ...result };
    };
    return { calls, spawn };
  }

  describe("the happy path (positive control)", function () {
    it("spawns `<host> prove <inputs>` once, with exactly the frozen environment", async function () {
      const w = await world();
      const s = spy();
      const { plan, output } = await runArchiveOnlyProve(
        w.input({
          callerEnv: { PATH: "/usr/bin", HOME: "/home/u", LD_PRELOAD: "/evil.so", SP1_WORKER_NUM_CORE_WORKERS: "2" },
        }),
        { images: present, spawn: s.spawn, guard: openGuard },
      );
      expect(s.calls).to.have.length(1);
      expect(plan.executable).to.equal(w.host);
      expect(plan.args).to.deep.equal(["prove", w.inputs]);
      expect(plan.env).to.deep.equal({
        PATH: "/usr/bin",
        HOME: "/home/u",
        SP1_PROVER: LOCAL_PROVER,
        SP1_GROTH16_CIRCUIT_PATH: w.root,
        SP1_GNARK_IMAGE: imageRef,
        DOCKER_CONTEXT: DOCKER_CONTEXT_FROZEN,
      });
      expect(plan.dropped).to.deep.equal(["LD_PRELOAD", "SP1_WORKER_NUM_CORE_WORKERS"]);
      expect(plan.circuitDir).to.equal(w.circuitDir);
      expect(output).to.deep.equal(JSON.parse(okOutput));
    });

    it("accepts caller values identical to the frozen ones", async function () {
      const w = await world();
      const env = {
        SP1_PROVER: "cpu",
        SP1_GROTH16_CIRCUIT_PATH: w.root,
        SP1_GNARK_IMAGE: imageRef,
        DOCKER_CONTEXT: "default",
      };
      const plan = prepareArchiveOnlyProve(w.input({ callerEnv: env }), present);
      expect(plan.env).to.deep.equal(env);
      expect(plan.dropped).to.deep.equal([]);
    });
  });

  describe("SP1 never starts when an input is missing (no fallback to its downloader or a tag)", function () {
    it("no accepted record", async function () {
      const w = await world();
      const s = spy();
      for (const r of [undefined, null, {}, { ...record, mirrors: [] }]) {
        expect(
          await refusalOf(() =>
            runArchiveOnlyProve(w.input({ record: r }), { images: present, spawn: s.spawn, guard: openGuard }),
          ),
        ).to.match(/^RECORD_INVALID/);
      }
      expect(s.calls).to.have.length(0);
    });

    it("no installation: the circuit directory or its root absent", async function () {
      const w = await world();
      const s = spy();
      const emptyRoot = join(w.work, "empty-root");
      mkdirSync(emptyRoot);
      expect(
        await refusalOf(() =>
          runArchiveOnlyProve(w.input({ circuitRoot: emptyRoot }), {
            images: present,
            spawn: s.spawn,
            guard: openGuard,
          }),
        ),
      ).to.equal("CIRCUIT_ARCHIVE_NOT_INSTALLED (CIRCUIT_ABSENT)");
      const absent = join(w.work, "absent");
      expect(
        await refusalOf(() =>
          runArchiveOnlyProve(w.input({ circuitRoot: absent }), { images: present, spawn: s.spawn, guard: openGuard }),
        ),
      ).to.equal("CIRCUIT_ARCHIVE_NOT_INSTALLED (ROOT_ABSENT)");
      expect(s.calls).to.have.length(0);
    });

    it("SP1_GROTH16_CIRCUIT_PATH pointing at a missing directory: the gate refuses itself", async function () {
      const w = await world();
      const s = spy();
      const absent = join(w.work, "absent");
      const got = await refusalOf(() =>
        runArchiveOnlyProve(w.input({ circuitRoot: absent, callerEnv: { SP1_GROTH16_CIRCUIT_PATH: absent } }), {
          images: present,
          spawn: s.spawn,
          guard: openGuard,
        }),
      );
      expect(got).to.equal("CIRCUIT_ARCHIVE_NOT_INSTALLED (ROOT_ABSENT)");
      expect(s.calls).to.have.length(0);
    });

    it("integrity: a member changed, an extra member, a member missing", async function () {
      const cases: [string, (dir: string) => void, string][] = [
        [
          "changed",
          (d) => writeFileSync(join(d, "groth16_pk.bin"), Buffer.alloc(3000)),
          "CIRCUIT_INTEGRITY_FAILED (DIGEST_MISMATCH)",
        ],
        ["extra", (d) => writeFileSync(join(d, "extra.bin"), "x"), "CIRCUIT_INTEGRITY_FAILED (UNEXPECTED_MEMBER)"],
        ["missing", (d) => rmSync(join(d, "constraints.json")), "CIRCUIT_INTEGRITY_FAILED (MISSING_MEMBER)"],
      ];
      for (const [what, damage, want] of cases) {
        const w = await world();
        writable(w.circuitDir);
        damage(w.circuitDir);
        const s = spy();
        expect(
          await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
          what,
        ).to.equal(want);
        expect(s.calls, what).to.have.length(0);
      }
    });

    it("the image: absent, present only under another digest, or unverifiable", async function () {
      const w = await world();
      const s = spy();
      const cases: [LocalImageDigests, string][] = [
        [() => null, "GNARK_IMAGE_NOT_LOCAL (ABSENT)"],
        [() => [otherDigest], "GNARK_IMAGE_NOT_LOCAL (DIGEST_NOT_LOCAL)"],
        [() => [], "GNARK_IMAGE_NOT_LOCAL (DIGEST_NOT_LOCAL)"],
        [
          () => {
            throw new Error("docker is not running");
          },
          "GNARK_IMAGE_NOT_LOCAL (UNVERIFIABLE)",
        ],
      ];
      for (const [images, want] of cases) {
        expect(
          await refusalOf(() => runArchiveOnlyProve(w.input(), { images, spawn: s.spawn, guard: openGuard })),
        ).to.equal(want);
      }
      expect(s.calls).to.have.length(0);
    });

    it("asks the image store about the record's digest-pinned reference, with the child's environment", async function () {
      const w = await world();
      const asked: [string, Record<string, string>][] = [];
      prepareArchiveOnlyProve(w.input(), (ref, env) => (asked.push([ref, env]), [ref]));
      expect(asked).to.have.length(1);
      expect(asked[0][0]).to.equal(imageRef);
      expect(asked[0][1].DOCKER_CONTEXT).to.equal("default");
    });

    it("the host executable and the inputs must be absolute regular files", async function () {
      const w = await world();
      const s = spy();
      const cases: [Partial<ProveGateInput>, string][] = [
        [{ hostExecutable: "mldsa65-host" }, "PROVE_INPUT_INVALID (RELATIVE)"],
        [{ hostExecutable: join(w.work, "absent") }, "PROVE_INPUT_INVALID (ABSENT)"],
        [{ hostExecutable: w.work }, "PROVE_INPUT_INVALID (NOT_A_FILE)"],
        [{ inputsPath: "inputs.json" }, "PROVE_INPUT_INVALID (RELATIVE)"],
        [{ inputsPath: join(w.work, "absent.json") }, "PROVE_INPUT_INVALID (ABSENT)"],
      ];
      for (const [over, want] of cases) {
        expect(
          await refusalOf(() =>
            runArchiveOnlyProve(w.input(over), { images: present, spawn: s.spawn, guard: openGuard }),
          ),
        ).to.equal(want);
      }
      expect(s.calls).to.have.length(0);
    });

    it("a wrong circuit version is a record the designation refuses", async function () {
      const w = await world();
      const s = spy();
      const r = { ...record, subject: { ...record.subject, circuitVersion: "v6.0.0" } };
      expect(
        await refusalOf(() =>
          runArchiveOnlyProve(w.input({ record: r }), { images: present, spawn: s.spawn, guard: openGuard }),
        ),
      ).to.equal("RECORD_INVALID (CIRCUIT_VERSION_MISMATCH)");
      expect(s.calls).to.have.length(0);
    });

    it("a tag-only gnark image in the record is refused", async function () {
      const w = await world();
      const s = spy();
      const r = { ...record, gnark: { ...record.gnark, repository: `${record.gnark.repository}:v6.1.0` } };
      expect(
        await refusalOf(() =>
          runArchiveOnlyProve(w.input({ record: r }), { images: present, spawn: s.spawn, guard: openGuard }),
        ),
      ).to.equal("RECORD_INVALID (GNARK_NOT_DIGEST_PINNED)");
      expect(s.calls).to.have.length(0);
    });
  });

  describe("hostile environments are refused before anything runs", function () {
    const hostile: [Record<string, string>, string][] = [
      [{ SP1_CIRCUIT_MODE: "dev" }, "ENV_REFUSED (CIRCUIT_MODE)"],
      [{ SP1_CIRCUIT_MODE: "release" }, "ENV_REFUSED (CIRCUIT_MODE)"],
      [{ sp1_circuit_mode: "dev" }, "ENV_REFUSED (CIRCUIT_MODE)"],
      [{ SP1_PROVER: "network" }, "ENV_REFUSED (PROVER_MODE)"],
      [{ SP1_PROVER: "mock" }, "ENV_REFUSED (PROVER_MODE)"],
      [{ SP1_PROVER: "" }, "ENV_REFUSED (PROVER_MODE)"],
      [{ Sp1_Prover: "cuda" }, "ENV_REFUSED (PROVER_MODE)"],
      [{ NETWORK_PRIVATE_KEY: "0x01" }, "ENV_REFUSED (PROVER_NETWORK)"],
      [{ NETWORK_RPC_URL: "https://rpc.invalid" }, "ENV_REFUSED (PROVER_NETWORK)"],
      [{ NETWORK_ANYTHING: "1" }, "ENV_REFUSED (PROVER_NETWORK)"],
      [{ SKIP_SIMULATION: "true" }, "ENV_REFUSED (PROVER_NETWORK)"],
      [{ WITHOUT_VK_VERIFICATION: "1" }, "ENV_REFUSED (VK_VERIFICATION_OFF)"],
      [{ SP1_PLONK_CIRCUIT_PATH: "/tmp/plonk" }, "ENV_REFUSED (ALTERNATE_CIRCUIT_PATH)"],
      [{ SP1_GROTH16_CIRCUIT_PATH: "/tmp/unverified" }, "ENV_REFUSED (CIRCUIT_PATH_CONFLICT)"],
      [{ SP1_GROTH16_CIRCUIT_PATH: "" }, "ENV_REFUSED (CIRCUIT_PATH_CONFLICT)"],
      [{ SP1_GNARK_IMAGE: "ghcr.io/succinctlabs/sp1-gnark:latest" }, "GNARK_IMAGE_NOT_PINNED (NO_DIGEST)"],
      [{ SP1_GNARK_IMAGE: "ghcr.io/succinctlabs/sp1-gnark:v6.1.0" }, "GNARK_IMAGE_NOT_PINNED (NO_DIGEST)"],
      [{ SP1_GNARK_IMAGE: "ghcr.io/succinctlabs/sp1-gnark@sha256:1234" }, "GNARK_IMAGE_NOT_PINNED (MALFORMED_DIGEST)"],
      [{ SP1_GNARK_IMAGE: otherDigest }, "GNARK_IMAGE_CONFLICT (OTHER_DIGEST)"],
      [{ DOCKER_HOST: "tcp://10.0.0.1:2375" }, "ENV_REFUSED (DOCKER_ENDPOINT_NOT_LOCAL)"],
      [{ DOCKER_HOST: "ssh://user@remote" }, "ENV_REFUSED (DOCKER_ENDPOINT_NOT_LOCAL)"],
      [{ DOCKER_HOST: "unix://" }, "ENV_REFUSED (DOCKER_ENDPOINT_NOT_LOCAL)"],
      [{ DOCKER_CONTEXT: "remote" }, "ENV_REFUSED (DOCKER_CONTEXT)"],
    ];
    for (const [env, want] of hostile) {
      it(`${JSON.stringify(env)}: ${want}`, async function () {
        const w = await world();
        const s = spy();
        let asked = 0;
        const images: LocalImageDigests = (ref) => ((asked += 1), [ref]);
        expect(
          await refusalOf(() =>
            runArchiveOnlyProve(w.input({ callerEnv: { PATH: "/usr/bin", ...env } }), {
              images,
              spawn: s.spawn,
              guard: openGuard,
            }),
          ),
        ).to.equal(want);
        expect(s.calls).to.have.length(0);
        expect(asked, "refused before the image store is asked").to.equal(0);
      });
    }

    it("a local docker socket passes; its value reaches the child unchanged", async function () {
      const w = await world();
      const host =
        process.platform === "win32" ? "npipe:////./pipe/docker_engine" : "unix:///run/user/1000/docker.sock";
      expect(prepareArchiveOnlyProve(w.input({ callerEnv: { DOCKER_HOST: host } }), present).env.DOCKER_HOST).to.equal(
        host,
      );
    });

    it("a docker endpoint is local only: an absolute unix socket, or a named pipe on this machine", function () {
      const frozen = { circuitRoot: "/opt/circuits", imageRef };
      const env = (v: string, platform: NodeJS.Platform) => buildProverEnv({ DOCKER_HOST: v }, frozen, platform);
      expect(env("unix:///var/run/docker.sock", "linux").env.DOCKER_HOST).to.equal("unix:///var/run/docker.sock");
      expect(env("npipe:////./pipe/docker_engine", "win32").env.DOCKER_HOST).to.equal("npipe:////./pipe/docker_engine");
      const refused: [string, NodeJS.Platform][] = [
        ["unix://relative.sock", "linux"],
        ["unix:///", "linux"],
        ["npipe:////./pipe/docker_engine", "linux"],
        ["npipe:////10.0.0.5/pipe/docker_engine", "win32"],
        ["npipe:////./pipe/a/b", "win32"],
        ["unix:///var/run/docker.sock", "win32"],
        ["tcp://127.0.0.1:2375", "linux"],
      ];
      for (const [v, platform] of refused) {
        expect(() => env(v, platform), `${v} on ${platform}`).to.throw(/DOCKER_ENDPOINT_NOT_LOCAL/);
      }
    });
  });

  describe("the constructed environment", function () {
    const frozen = { circuitRoot: "/opt/circuits", imageRef };
    it("holds only pass-through basics and the frozen values, never a dropped variable", function () {
      const caller: Record<string, string> = {
        LD_PRELOAD: "/evil.so",
        LD_LIBRARY_PATH: "/evil",
        DYLD_INSERT_LIBRARIES: "/evil.dylib",
        HTTPS_PROXY: "http://proxy.invalid",
        SP1_DUMP: "1",
        SP1_RECORD_WRITE_DIR: "/tmp/x",
        SP1_WORKER_USE_FIXED_PK: "true",
        DOCKER_CERT_PATH: "/certs",
        RUST_LOG: "info",
        PATH: "/usr/bin",
      };
      const { env, dropped } = buildProverEnv(caller, frozen, "linux");
      for (const k of Object.keys(env)) {
        expect(PASS_THROUGH_ENV.includes(k) || (FROZEN_ENV as readonly string[]).includes(k), k).to.equal(true);
      }
      for (const k of Object.keys(REFUSED_ENV)) expect(env, k).to.not.have.property(k);
      expect(env).to.deep.equal({
        RUST_LOG: "info",
        PATH: "/usr/bin",
        SP1_PROVER: "cpu",
        SP1_GROTH16_CIRCUIT_PATH: "/opt/circuits",
        SP1_GNARK_IMAGE: imageRef,
        DOCKER_CONTEXT: "default",
      });
      expect(dropped).to.deep.equal(
        [
          "DOCKER_CERT_PATH",
          "DYLD_INSERT_LIBRARIES",
          "HTTPS_PROXY",
          "LD_LIBRARY_PATH",
          "LD_PRELOAD",
          "SP1_DUMP",
          "SP1_RECORD_WRITE_DIR",
          "SP1_WORKER_USE_FIXED_PK",
        ].sort(),
      );
    });
    it("matches pass-through names case-insensitively on Windows only, and skips unset values", function () {
      expect(buildProverEnv({ Path: "C:\\Windows", SystemRoot: "C:\\Windows" }, frozen, "win32").env).to.include({
        Path: "C:\\Windows",
        SystemRoot: "C:\\Windows",
      });
      const linux = buildProverEnv({ Path: "/x", path: "/y", HOME: undefined }, frozen, "linux");
      expect(linux.env).to.not.have.property("Path");
      expect(linux.env).to.not.have.property("HOME");
      expect(linux.dropped).to.deep.equal(["Path", "path"]);
    });
  });

  describe("the circuit root", function () {
    it("must be absolute, normalized and safe inside docker's -v src:dest", function () {
      expect(circuitRootError("/opt/circuits", "linux")).to.equal(null);
      expect(circuitRootError("circuits", "linux")).to.equal("RELATIVE");
      expect(circuitRootError("", "linux")).to.equal("RELATIVE");
      expect(circuitRootError("C:\\circuits", "linux")).to.equal("RELATIVE");
      expect(circuitRootError("/opt/circuits/", "linux")).to.equal("NOT_NORMALIZED");
      expect(circuitRootError("/opt/x/../circuits", "linux")).to.equal("NOT_NORMALIZED");
      expect(circuitRootError("/opt//circuits", "linux")).to.equal("NOT_NORMALIZED");
      expect(circuitRootError("/opt/a:/etc", "linux")).to.equal("MOUNT_UNSAFE_PATH");
      expect(circuitRootError("/opt/a,b", "linux")).to.equal("MOUNT_UNSAFE_PATH");
      expect(circuitRootError("C:\\circuits", "win32")).to.equal(null);
      expect(circuitRootError("C:\\circuits\\", "win32")).to.equal("NOT_NORMALIZED");
      expect(circuitRootError("C:/circuits", "win32")).to.equal("NOT_NORMALIZED");
      expect(circuitRootError("circuits", "win32")).to.equal("RELATIVE");
      expect(circuitRootError("C:\\a:b", "win32")).to.equal("MOUNT_UNSAFE_PATH");
      expect(circuitRootError("\\\\fileserver\\share\\circuits", "win32")).to.equal("UNC_PATH");
      expect(circuitRootError("//fileserver/share/circuits", "win32")).to.equal("UNC_PATH");
      expect(circuitRootError("//opt/circuits", "linux")).to.equal("NOT_NORMALIZED");
    });
    it("an unsafe root is refused before anything runs", async function () {
      const w = await world();
      const s = spy();
      expect(
        await refusalOf(() =>
          runArchiveOnlyProve(w.input({ circuitRoot: "circuits" }), {
            images: present,
            spawn: s.spawn,
            guard: openGuard,
          }),
        ),
      ).to.equal("CIRCUIT_ROOT_INVALID (RELATIVE)");
      // An absolute root with a trailing separator verifies on disk, but SP1 would be given another spelling of it.
      expect(
        await refusalOf(() =>
          runArchiveOnlyProve(w.input({ circuitRoot: `${w.root}${sep}` }), {
            images: present,
            spawn: s.spawn,
            guard: openGuard,
          }),
        ),
      ).to.equal("CIRCUIT_ROOT_INVALID (NOT_NORMALIZED)");
      expect(s.calls).to.have.length(0);
    });
  });

  describe("after the host runs", function () {
    it("an oversized output reported by the spawner stays PROOF_OUTPUT_REFUSED", async function () {
      const w = await world();
      const s = spy(async () => {
        throw new CircuitToolingError("PROOF_OUTPUT_REFUSED", "OUTPUT_TOO_LARGE", "synthetic");
      });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("PROOF_OUTPUT_REFUSED (OUTPUT_TOO_LARGE)");
    });
    it("a non-zero exit is PROVER_FAILED", async function () {
      const w = await world();
      const s = spy({ status: 3 });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("PROVER_FAILED (EXIT)");
      const k = spy({ status: null, signal: "SIGKILL" });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: k.spawn, guard: openGuard })),
      ).to.equal("PROVER_FAILED (EXIT)");
    });
    it("a spawn that throws is PROVER_SPAWN_FAILED", async function () {
      const w = await world();
      const s = spy(async () => {
        throw new Error("ENOENT");
      });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("PROVER_SPAWN_FAILED (SPAWN)");
    });
    it("an installation changed during the run is CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE", async function () {
      const w = await world();
      const s = spy(async () => {
        writable(w.circuitDir);
        writeFileSync(join(w.circuitDir, "groth16_pk.bin"), Buffer.alloc(3000));
        return { status: 0, signal: null, stdout: okOutput };
      });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE (DIGEST_MISMATCH)");
      const gone = await world();
      const g = spy(async () => {
        writable(gone.circuitDir);
        rmSync(gone.circuitDir, { recursive: true, force: true });
        return { status: 0, signal: null, stdout: okOutput };
      });
      expect(
        await refusalOf(() => runArchiveOnlyProve(gone.input(), { images: present, spawn: g.spawn, guard: openGuard })),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE (CIRCUIT_ABSENT)");
    });
    it("the proof must be JSON naming the designated PROGRAM_VKEY, with hex values", async function () {
      expect(proofOutput(`noise\n${okOutput}\n\n`, anchor)).to.deep.equal(JSON.parse(okOutput));
      const cases: [string, string][] = [
        ["", "PROOF_OUTPUT_REFUSED (NOT_JSON)"],
        ["not json", "PROOF_OUTPUT_REFUSED (NOT_JSON)"],
        ["null", "PROOF_OUTPUT_REFUSED (VKEY_MISMATCH)"],
        [
          JSON.stringify({ vkey: `0x${"00".repeat(32)}`, publicValues: "0x", proofBytes: "0x00" }),
          "PROOF_OUTPUT_REFUSED (VKEY_MISMATCH)",
        ],
        [
          JSON.stringify({ vkey: anchor.programVKey, publicValues: "0xZZ", proofBytes: "0x00" }),
          "PROOF_OUTPUT_REFUSED (SHAPE)",
        ],
        [
          JSON.stringify({ vkey: anchor.programVKey, publicValues: "0x0", proofBytes: "0x00" }),
          "PROOF_OUTPUT_REFUSED (SHAPE)",
        ],
        [
          JSON.stringify({ vkey: anchor.programVKey, publicValues: "0x", proofBytes: "0x" }),
          "PROOF_OUTPUT_REFUSED (SHAPE)",
        ],
        [
          JSON.stringify({ vkey: anchor.programVKey, publicValues: "0x", proofBytes: "0xdeadbeef00" }),
          "PROOF_OUTPUT_REFUSED (SELECTOR_MISMATCH)",
        ],
        [
          JSON.stringify({ vkey: anchor.programVKey, publicValues: "0x", proofBytes: `0x${selector.slice(0, 6)}` }),
          "PROOF_OUTPUT_REFUSED (SELECTOR_MISMATCH)",
        ],
      ];
      for (const [stdout, want] of cases)
        expect(await refusalOf(() => proofOutput(stdout, anchor)), stdout).to.equal(want);
      const w = await world();
      const s = spy({ stdout: "no proof here" });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("PROOF_OUTPUT_REFUSED (NOT_JSON)");
    });
  });

  describe("the run lock and the installation's identity", function () {
    it("locks the root before the host starts and releases it after, whatever happens", async function () {
      const w = await world();
      const events: string[] = [];
      const guard: RootGuard = (root, dir) => {
        events.push(`lock ${root === w.root} ${dir === w.circuitDir}`);
        return { release: () => void events.push("release") };
      };
      const s = spy(async (plan) => (events.push("spawn"), { status: 0, signal: null, stdout: okOutput }));
      await runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard });
      expect(events).to.deep.equal(["lock true true", "spawn", "release"]);
      for (const failing of [
        spy({ status: 1 }),
        spy(async () => {
          throw new Error("ENOENT");
        }),
      ]) {
        events.length = 0;
        expect(
          await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: failing.spawn, guard })),
        ).to.match(/^PROVER_(FAILED|SPAWN_FAILED)/);
        expect(events).to.deep.equal(["lock true true", "release"]);
      }
    });

    it("never spawns when the lock cannot be taken", async function () {
      const w = await world();
      const s = spy();
      const refusing: RootGuard = () => {
        throw new CircuitToolingError("PROVE_HOST_UNSUPPORTED", "RUNS_AS_ROOT", "synthetic");
      };
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: refusing })),
      ).to.equal("PROVE_HOST_UNSUPPORTED (RUNS_AS_ROOT)");
      expect(s.calls).to.have.length(0);
    });

    it("re-verifies under the lock: a member changed after the gate's first check is refused before the spawn", async function () {
      const w = await world();
      const s = spy();
      const damaging: RootGuard = () => {
        writable(w.circuitDir);
        writeFileSync(join(w.circuitDir, "groth16_pk.bin"), Buffer.alloc(3000));
        return { release() {} };
      };
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: damaging })),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED (DIGEST_MISMATCH)");
      expect(s.calls).to.have.length(0);
    });

    it("the installation moved away and re-created with the same bytes during the run is REPLACED", async function () {
      const w = await world();
      const s = spy(async () => {
        // What SP1 does when the verified directory disappears mid-run: it fetches the circuit again.
        writable(w.circuitDir);
        renameSync(w.circuitDir, join(w.work, "moved-away"));
        cpSync(join(w.work, "moved-away"), w.circuitDir, { recursive: true });
        rmSync(join(w.work, "moved-away"), { recursive: true, force: true });
        return { status: 0, signal: null, stdout: okOutput };
      });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE (REPLACED)");
    });

    it("an integrity failure after a failed run is reported over the run's failure", async function () {
      const w = await world();
      const s = spy(async () => {
        writable(w.circuitDir);
        writeFileSync(join(w.circuitDir, "extra.bin"), "x");
        throw new Error("the host crashed");
      });
      expect(
        await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
      ).to.equal("CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE (UNEXPECTED_MEMBER)");
    });

    it("prepare alone verifies the installation too (a dry run of the gate)", async function () {
      const w = await world();
      writable(w.circuitDir);
      writeFileSync(join(w.circuitDir, "groth16_circuit.bin"), Buffer.alloc(1500));
      expect(await refusalOf(() => prepareArchiveOnlyProve(w.input(), present))).to.equal(
        "CIRCUIT_INTEGRITY_FAILED (DIGEST_MISMATCH)",
      );
    });

    it("a root holding anything besides the verified version is refused (a host for another circuit would read it)", async function () {
      for (const extra of ["v6.0.0", "notes.txt"]) {
        const w = await world();
        if (extra === "notes.txt") writeFileSync(join(w.root, extra), "x");
        else mkdirSync(join(w.root, extra));
        const s = spy();
        expect(
          await refusalOf(() => runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn, guard: openGuard })),
          extra,
        ).to.equal("CIRCUIT_ROOT_INVALID (UNEXPECTED_ENTRY)");
        expect(s.calls).to.have.length(0);
      }
    });

    it("the root guard refuses Windows and the superuser, before touching anything", function () {
      expect(() => posixRootGuardFor("win32", 1000)("C:\\circuits", "C:\\circuits\\v6.1.0")).to.throw(
        /PROVE_HOST_UNSUPPORTED \(WINDOWS\)/,
      );
      expect(() => posixRootGuardFor("linux", 0)("/nonexistent/circuits", "/nonexistent/circuits/v6.1.0")).to.throw(
        /PROVE_HOST_UNSUPPORTED \(RUNS_AS_ROOT\)/,
      );
      if (process.platform === "win32") {
        expect(() => posixRootGuard("C:\\circuits", "C:\\circuits\\v6.1.0")).to.throw(/WINDOWS/);
      }
    });

    it("securePathError judges every ancestor: owner, writability, stickiness, links", function () {
      const tree: Record<string, { uid: number; mode: number }> = {
        "/": { uid: 0, mode: 0o40755 },
        "/srv": { uid: 0, mode: 0o40755 },
        "/srv/c": { uid: 1000, mode: 0o40755 },
      };
      const fs = (over: Record<string, { uid: number; mode: number }> = {}, real = (p: string) => p) => ({
        lstat: (p: string) => ({ ...tree, ...over })[p],
        realpath: real,
      });
      expect(securePathError("/srv/c", 1000, fs())).to.equal(null);
      expect(securePathError("/srv/c", 1001, fs())).to.equal("NOT_OWNED");
      expect(securePathError("/srv/c", 1000, fs({ "/srv/c": { uid: 1000, mode: 0o40775 } }))).to.equal(
        "WRITABLE_BY_OTHERS",
      );
      expect(securePathError("/srv/c", 1000, fs({ "/srv/c": { uid: 1000, mode: 0o41777 } }))).to.equal(
        "WRITABLE_BY_OTHERS",
      );
      expect(securePathError("/srv/c", 1000, fs({ "/srv": { uid: 1002, mode: 0o40755 } }))).to.equal(
        "FOREIGN_ANCESTOR",
      );
      expect(securePathError("/srv/c", 1000, fs({ "/srv": { uid: 1000, mode: 0o40755 } }))).to.equal(null);
      expect(securePathError("/srv/c", 1000, fs({ "/srv": { uid: 0, mode: 0o40777 } }))).to.equal("WRITABLE_ANCESTOR");
      expect(securePathError("/srv/c", 1000, fs({ "/srv": { uid: 0, mode: 0o40775 } }))).to.equal("WRITABLE_ANCESTOR");
      expect(securePathError("/srv/c", 1000, fs({ "/srv": { uid: 0, mode: 0o41777 } }))).to.equal(null);
      expect(securePathError("/srv/c", 1000, fs({ "/": { uid: 0, mode: 0o40777 } }))).to.equal("WRITABLE_ANCESTOR");
      expect(
        securePathError(
          "/srv/c",
          1000,
          fs({}, () => "/elsewhere/c"),
        ),
      ).to.equal("LINKED_PATH");
      const absent = () => {
        throw new Error("ENOENT");
      };
      expect(securePathError("/srv/c", 1000, fs({}, absent))).to.equal("ABSENT");
    });

    it("posixRootGuard locks the root: no other version directory, no rename of the verified one, until release", async function () {
      if (process.platform === "win32" || process.getuid?.() === 0) this.skip();
      const w = await world();
      const before = statSync(w.root).mode & 0o7777;
      const lock = posixRootGuard(w.root, w.circuitDir);
      try {
        expect(statSync(w.root).mode & 0o222).to.equal(0);
        expect(() => mkdirSync(join(w.root, "v6.1.1"))).to.throw(/EACCES/);
        expect(() => renameSync(w.circuitDir, join(w.root, "elsewhere"))).to.throw(/EACCES/);
      } finally {
        lock.release();
      }
      expect(statSync(w.root).mode & 0o7777).to.equal(before);
      // The production run takes the same lock: during the spawn the root is read-only.
      let modeDuringSpawn = -1;
      const s = spy(
        async () => ((modeDuringSpawn = statSync(w.root).mode & 0o777), { status: 0, signal: null, stdout: okOutput }),
      );
      await runArchiveOnlyProve(w.input(), { images: present, spawn: s.spawn });
      expect(modeDuringSpawn & 0o222).to.equal(0);
      expect(statSync(w.root).mode & 0o7777).to.equal(before);
    });

    it("posixRootGuard refuses a root or member others can write, and a linked root", async function () {
      if (process.platform === "win32" || process.getuid?.() === 0) this.skip();
      const w = await world();
      chmodSync(w.root, 0o775);
      expect(() => posixRootGuard(w.root, w.circuitDir)).to.throw(/CIRCUIT_ROOT_INVALID \(WRITABLE_BY_OTHERS\)/);
      chmodSync(w.root, 0o755);
      chmodSync(join(w.circuitDir, "groth16_pk.bin"), 0o464);
      expect(() => posixRootGuard(w.root, w.circuitDir)).to.throw(/CIRCUIT_ROOT_INVALID \(WRITABLE_BY_OTHERS\)/);
      chmodSync(join(w.circuitDir, "groth16_pk.bin"), 0o444);
      const link = join(w.work, "linked-root");
      symlinkSync(w.root, link, "dir");
      expect(() => posixRootGuard(link, join(link, "v6.1.0"))).to.throw(/CIRCUIT_ROOT_INVALID \(LINKED_PATH\)/);
      const lock = posixRootGuard(w.root, w.circuitDir);
      lock.release();
    });

    it("securePathError: ancestors writable by others only when sticky", function () {
      if (process.platform === "win32") this.skip();
      const uid = process.getuid?.() ?? -1;
      const base = dirs.make();
      const open = join(base, "open");
      mkdirSync(join(open, "root"), { recursive: true });
      chmodSync(open, 0o777);
      expect(securePathError(join(open, "root"), uid)).to.equal("WRITABLE_ANCESTOR");
      chmodSync(open, 0o1777);
      expect(securePathError(join(open, "root"), uid)).to.equal(null);
      chmodSync(open, 0o755);
      expect(securePathError(join(open, "root"), uid)).to.equal(null);
      expect(securePathError(join(open, "root"), uid + 1)).to.equal("NOT_OWNED");
      expect(securePathError(join(open, "absent"), uid)).to.equal("ABSENT");
    });
  });

  describe("spawnHost (a real child process)", function () {
    it("kills a child whose stdout passes 64 MiB at once, instead of buffering it", async function () {
      this.timeout(20_000);
      const w = await world();
      const script = join(w.work, "flood.cjs");
      // Writes just over the cap, then would idle for a minute: only a kill ends it within the test's timeout.
      writeFileSync(
        script,
        "const b = Buffer.alloc(1 << 20, 97); let n = 65; const go = () => { while (n > 0) { n--; if (!process.stdout.write(b)) return process.stdout.once('drain', go); } setTimeout(() => {}, 60000); }; go();",
      );
      const started = Date.now();
      expect(
        await refusalOf(() =>
          spawnHost({
            executable: process.execPath,
            args: [script],
            env: {},
            dropped: [],
            circuitDir: "",
            imageRef,
            record,
          }),
        ),
      ).to.equal("PROOF_OUTPUT_REFUSED (OUTPUT_TOO_LARGE)");
      expect(Date.now() - started).to.be.lessThan(15_000);
    });
    it("runs without a shell, with exactly the given environment, and reports the exit status", async function () {
      const w = await world();
      const script = join(w.work, "print-env.cjs");
      writeFileSync(
        script,
        "process.stdout.write(JSON.stringify(process.env)); process.exitCode = Number(process.argv[2] ?? 0);",
      );
      const env = { ONLY_THIS: "1", SP1_PROVER: "cpu" };
      const base: ProvePlan = {
        executable: process.execPath,
        args: [script, "0"],
        env,
        dropped: [],
        circuitDir: w.circuitDir,
        imageRef,
        record,
      };
      const ok = await spawnHost(base);
      expect(ok.status).to.equal(0);
      const childEnv = JSON.parse(ok.stdout);
      // libuv adds these on Windows whatever the environment block says (process.c required_vars); none selects a
      // circuit, prover or image, and SP1_GROTH16_CIRCUIT_PATH is frozen, so the home they imply is never read.
      const windowsRequired = [
        "HOMEDRIVE",
        "HOMEPATH",
        "LOGONSERVER",
        "PATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
      ];
      for (const k of Object.keys(childEnv)) {
        const added = process.platform === "win32" && windowsRequired.includes(k.toUpperCase());
        expect(added || k in env, `the child inherited ${k}`).to.equal(true);
      }
      expect(childEnv.ONLY_THIS).to.equal("1");
      const failed = await spawnHost({ ...base, args: [script, "7"] });
      expect(failed.status).to.equal(7);
      expect(await refusalOf(() => spawnHost({ ...base, executable: join(w.work, "no-such-binary") }))).to.match(
        /^UNEXPECTED: .*ENOENT/,
      );
      const shell = await spawnHost({
        ...base,
        args: ["-e", "process.stdout.write(process.argv.slice(1).join('|'))", "$(id)", ";", "&&"],
      });
      expect(shell.stdout).to.equal("$(id)|;|&&");
    });
  });
});

/** An installation is read-only; a test that damages one makes it writable first. */
function writable(dir: string): void {
  chmodSync(dir, 0o700);
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isFile()) chmodSync(join(dir, e.name), 0o600);
    else if (e.isDirectory()) writable(join(dir, e.name));
  }
}
