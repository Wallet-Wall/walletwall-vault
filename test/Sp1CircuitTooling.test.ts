/**
 * SP1-PA2A: the circuit-tooling contract (scripts/lib/sp1-circuit-tooling.ts, evidence/zk/sp1-impl/circuit-tooling.json).
 *
 * Tooling is not an artifact and an artifact is not proving. These tests hold the lane to that: the committed record
 * derives TOOLING_READY_NO_ARTIFACT while PROVING_AVAILABILITY stays OWNER_DOWNLOAD_REQUIRED; no synthetic fixture can
 * satisfy designation d1's anchor or sit where proving availability would count it; the upstream observation is bound
 * to the host lockfile and its script; and every variable the pinned SP1 reads to pick the circuit, prover or gnark
 * image is frozen or refused by the gate. Offline: no network, docker, SP1 toolchain or circuit archive.
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";

import {
  ARCHIVE_RECORD_SCHEMA,
  PROVENANCE_PAX_KEY,
  RECORD_FIELDS,
  archiveRecordErrors,
} from "../scripts/lib/sp1-circuit-archive";
import {
  FIXTURES_DIR,
  SAFE_ARCHIVE_REL,
  SAFE_FILES,
  SAFE_RECORD_REL,
  SYNTHETIC_ANCHOR,
  SYNTHETIC_ANCHOR_REL,
  gz,
  safeTar,
  syntheticRecord,
  tarBytes,
} from "../scripts/lib/sp1-circuit-fixtures";
import {
  ARCHIVE_JSON_SCHEMA_REL,
  CENSUS_OBSERVATIONS_REL,
  STATES,
  TOOLING_REL,
  TOOLING_SCHEMA,
  UPSTREAM_OBSERVATION_REL,
  UPSTREAM_SCRIPT_REL,
  authoritativeRecordError,
  censusObservationErrors,
  censusPolicyErrors,
  committedProductionAnchor,
  serializeCensus,
  committedProductionRecord,
  envClass,
  environmentReads,
  gateCoverageErrors,
  measureUpstream,
  productionAnchor,
  readUpstreamFacts,
  toolingErrors,
  toolingState,
  uncommittedEvidenceError,
  upstreamObservationErrors,
  type UpstreamObservation,
} from "../scripts/lib/sp1-circuit-tooling";
import {
  PROVING_ARCHIVES_DIR,
  PROVING_AVAILABILITY_REL,
  archiveRecordsIn,
  provingAvailabilityErrors,
} from "../scripts/lib/sp1-proving-availability";
import { refusalOf, symlinkOrSkip, tempDirs } from "./helpers/circuit-tooling";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const read = (rel: string) => readFileSync(resolve(rel));
const insideGit =
  spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { encoding: "utf8" }).stdout?.trim() === "true";
const committedObservation = () => JSON.parse(read(UPSTREAM_OBSERVATION_REL).toString("utf8")) as UpstreamObservation;

/** Excerpts shaped like the pinned crates' sources: what SP1-PA2A read, in the form the measurement must find. */
const BUILD_RS = `
pub const CIRCUIT_ARTIFACTS_URL_BASE: &str = "https://sp1-circuits.s3-us-east-2.amazonaws.com";

pub(crate) fn use_development_mode() -> bool {
    std::env::var("SP1_CIRCUIT_MODE").unwrap_or("release".to_string()) == "dev"
}

pub fn groth16_circuit_artifacts_dir() -> Result<PathBuf> {
    let base_path = match std::env::var("SP1_GROTH16_CIRCUIT_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
            home_dir.join(".sp1").join("circuits/groth16")
        }
    };
    Ok(base_path.join(SP1_CIRCUIT_VERSION))
}

pub async fn try_install_circuit_artifacts(artifacts_type: &str) -> Result<PathBuf> {
    if build_dir.exists() {
        tracing::info!("already there");
    } else {
        install_circuit_artifacts(build_dir.clone(), artifacts_type).await?;
    }
    Ok(build_dir)
}

pub async fn install_circuit_artifacts(build_dir: PathBuf, artifacts_type: &str) -> Result<()> {
    let res =
        Command::new("tar").args(["-Pxzf", tar_path_str, "-C", build_dir_str]).output().await?;
    Ok(())
}

pub async fn download_file(
    client: &Client,
) -> Result<()> {
    Ok(())
}
`;
const ENV_RS = `
impl EnvProver {
    pub fn from_env_with_opts_and_machine(
        core_opts: Option<SP1CoreOpts>,
    ) -> Self {
        let prover = match std::env::var("SP1_PROVER") {
            Ok(prover) => prover,
            Err(_) => "cpu".to_string(),
        };

        match prover.as_str() {
            "cpu" => Self::Cpu(x),
            "mock" => Self::Mock(x),
            #[cfg(not(feature = "network"))]
            "network" => panic!("off"),
            _ => unreachable!(),
        }
    }
}
`;
const DOCKER_RS = `
fn get_docker_image() -> String {
    std::env::var("SP1_GNARK_IMAGE")
        .unwrap_or_else(|_| format!("ghcr.io/succinctlabs/sp1-gnark:{SP1_CIRCUIT_VERSION}"))
}

fn call_docker(args: &[&str], mounts: &[(&str, &str)]) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm"]);
    for (src, dest) in mounts {
        cmd.arg("-v").arg(format!("{src}:{dest}"));
    }
    Ok(())
}
`;
const NETWORK_RS = `let k = std::env::var("NETWORK_PRIVATE_KEY"); let o = env::var_os( "HOME" );`;
const SOURCES: Record<string, Record<string, string>> = {
  "sp1-prover": { SP1_CIRCUIT_VERSION: "v6.1.0\n", "src/build.rs": BUILD_RS },
  "sp1-sdk": { "src/blocking/env/mod.rs": ENV_RS, "src/network.rs": NETWORK_RS, "tests/t.rs": 'env::var("NOT_SRC")' },
  "sp1-recursion-gnark-ffi": { "src/ffi/docker.rs": DOCKER_RS },
};
const srcOf =
  (sources: Record<string, Record<string, string>>) =>
  (crate: string, member: string): string => {
    const s = sources[crate]?.[member];
    if (s === undefined) throw new Error(`no ${crate}/${member}`);
    return s;
  };

describe("SP1-PA2A circuit tooling contract", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());

  describe("the committed state", function () {
    it("validates: TOOLING_READY_NO_ARTIFACT, PROVING_AVAILABILITY still OWNER_DOWNLOAD_REQUIRED", async function () {
      this.timeout(120_000);
      expect(await toolingErrors(".")).to.deep.equal([]);
      const r = JSON.parse(read(TOOLING_REL).toString("utf8"));
      expect(r.schema).to.equal(TOOLING_SCHEMA);
      expect(r.state).to.equal("TOOLING_READY_NO_ARTIFACT");
      expect(r.provingAvailability.status).to.equal("OWNER_DOWNLOAD_REQUIRED");
      expect(r.provingAvailability.sha256).to.equal(sha256(read(PROVING_AVAILABILITY_REL)));
      expect(r.archiveRecord.productionRecords).to.equal(0);
      expect(r.selfTest.hostile).to.have.length(153);
      expect(r.archiveRecord.schema).to.equal("walletwall.sp1-proving-archive.v2");
      expect(r.archiveRecord.ignoredMetadata.derivedFrom.archive).to.deep.equal({
        bytes: 6211807514,
        sha256: "18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810",
      });
      expect(r.selfTest.productionAnchorRefusesFixtures).to.deep.equal(["SUBJECT_MISMATCH", "VK_MISMATCH"]);
      expect(STATES.filter((s) => s.reachableInThisLane).map((s) => s.state)).to.deep.equal([
        "TOOLING_NOT_PRESENT",
        "TOOLING_READY_NO_ARTIFACT",
      ]);
    });

    it("leaves proving availability exactly as its own validator derives it, with no archive record", function () {
      expect(provingAvailabilityErrors(".")).to.deep.equal([]);
      const pa = JSON.parse(read(PROVING_AVAILABILITY_REL).toString("utf8"));
      expect(pa.status).to.equal("OWNER_DOWNLOAD_REQUIRED");
      expect(pa.archives.records).to.equal(0);
      expect(archiveRecordsIn(".")).to.deep.equal([]);
    });

    it("refuses a stale tooling record", async function () {
      this.timeout(120_000);
      const repo = dirs.make();
      for (const p of ["evidence", "scripts", "test/fixtures", "zkvm/host/Cargo.lock"]) {
        cpSync(resolve(p), join(repo, p), { recursive: true });
      }
      writeFileSync(join(repo, TOOLING_REL), "{}\n");
      expect(await toolingErrors(repo)).to.deep.equal([
        `${TOOLING_REL} is not what the evidence and the self-test derive: regenerate it`,
      ]);
    });

    it("refuses to derive anything while proving availability is other than OWNER_DOWNLOAD_REQUIRED", async function () {
      this.timeout(120_000);
      const repo = dirs.make();
      for (const p of ["evidence", "scripts", "test/fixtures", "zkvm/host/Cargo.lock"]) {
        cpSync(resolve(p), join(repo, p), { recursive: true });
      }
      const pa = JSON.parse(read(PROVING_AVAILABILITY_REL).toString("utf8"));
      pa.status = "LOCAL_COPY_NOT_ARCHIVED";
      writeFileSync(join(repo, PROVING_AVAILABILITY_REL), JSON.stringify(pa));
      expect(await toolingErrors(repo)).to.deep.equal([
        "proving availability is LOCAL_COPY_NOT_ARCHIVED: this lane leaves it OWNER_DOWNLOAD_REQUIRED, and a change needs its own lane",
      ]);
    });

    it("refuses to derive anything from census observations that are not one census", async function () {
      this.timeout(120_000);
      const repo = dirs.make();
      for (const p of ["evidence", "scripts", "test/fixtures", "zkvm/host/Cargo.lock"]) {
        cpSync(resolve(p), join(repo, p), { recursive: true });
      }
      const other = JSON.parse(read(CENSUS_OBSERVATIONS_REL[1]).toString("utf8"));
      other.tar.entries += 1;
      writeFileSync(join(repo, CENSUS_OBSERVATIONS_REL[1]), JSON.stringify(other));
      expect(await toolingErrors(repo)).to.deep.equal(["the census observations are not one census"]);
    });

    it("never derives an archived state: a production record, a failed self-test", function () {
      expect(toolingState({ productionArchiveRecords: 0, selfTestPassed: true })).to.equal("TOOLING_READY_NO_ARTIFACT");
      expect(toolingState({ productionArchiveRecords: 0, selfTestPassed: false })).to.equal("TOOLING_NOT_PRESENT");
      expect(() => toolingState({ productionArchiveRecords: 1, selfTestPassed: true })).to.throw(
        /ARCHIVED_VERIFIED_UNEXERCISED is not reachable/,
      );
    });
  });

  describe("the production anchor", function () {
    it("is designation d1's circuit, verifier and verifying key", function () {
      const d1 = JSON.parse(read("evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json").toString("utf8"));
      expect(productionAnchor(".")).to.deep.equal({
        designation: "mldsa65-withdrawal-d1",
        circuitVersion: "v6.1.0",
        programVKey: d1.programVKey,
        verifier: {
          version: "v6.1.0",
          runtimeCodeKeccak: d1.verifier.runtimeCodeKeccak,
          verifierHash: d1.verifier.verifierHash,
        },
        verifyingKey: { sha256: "0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696", bytes: 492 },
      });
    });

    it("refuses evidence that does not name one circuit and key", function () {
      const edits: ((pa: any) => void)[] = [
        (pa) => (pa.designations = ["another"]),
        (pa) => (pa.expectedArtifacts.circuitVersion = "v6.0.0"),
        (pa) => (pa.expectedArtifacts.members[0].sha256 = `0x${"00".repeat(32)}`),
        (pa) => (pa.expectedArtifacts.members[0].bytes = "492"),
        (pa) => (pa.expectedArtifacts.members = []),
      ];
      for (const edit of edits) {
        const repo = dirs.make();
        cpSync(resolve("evidence/zk/sp1/designations"), join(repo, "evidence/zk/sp1/designations"), {
          recursive: true,
        });
        const pa = JSON.parse(read(PROVING_AVAILABILITY_REL).toString("utf8"));
        edit(pa);
        mkdirSync(join(repo, "evidence/zk/sp1-impl"), { recursive: true });
        writeFileSync(join(repo, PROVING_AVAILABILITY_REL), JSON.stringify(pa));
        expect(() => productionAnchor(repo)).to.throw(/do not name one circuit and verifying key/);
      }
      const empty = dirs.make();
      mkdirSync(join(empty, "evidence/zk/sp1-impl"), { recursive: true });
      writeFileSync(join(empty, PROVING_AVAILABILITY_REL), read(PROVING_AVAILABILITY_REL));
      expect(() => productionAnchor(empty)).to.throw(/do not name one circuit and verifying key/);
    });
  });

  describe("no synthetic fixture can become availability evidence", function () {
    it("the production anchor refuses the fixture record, and any record made for the synthetic anchor", function () {
      const anchor = productionAnchor(".");
      const fixture = JSON.parse(read(SAFE_RECORD_REL).toString("utf8"));
      const why = archiveRecordErrors(fixture, anchor).map((e) => e.reason);
      expect(why).to.include("SUBJECT_MISMATCH");
      expect(why).to.include("VK_MISMATCH");
      // Even relabeled with d1's subject, the synthetic groth16_vk.bin is not d1's key.
      const relabeled = clone(fixture);
      relabeled.subject = {
        circuitSystem: "groth16",
        circuitVersion: anchor.circuitVersion,
        designation: anchor.designation,
        programVKey: anchor.programVKey,
        verifier: anchor.verifier,
        verifyingKey: { file: "groth16_vk.bin", ...anchor.verifyingKey },
      };
      expect(archiveRecordErrors(relabeled, anchor).map((e) => e.reason)).to.deep.equal(["VK_MISMATCH"]);
    });

    it("fixtures live under test/fixtures, never where proving availability counts records", function () {
      expect(FIXTURES_DIR.startsWith("test/fixtures/")).to.equal(true);
      expect(PROVING_ARCHIVES_DIR.startsWith("evidence/")).to.equal(true);
      for (const rel of [SAFE_ARCHIVE_REL, SAFE_RECORD_REL, SYNTHETIC_ANCHOR_REL]) {
        expect(rel.startsWith(`${FIXTURES_DIR}/`), rel).to.equal(true);
        expect(authoritativeRecordError(rel, "."), rel).to.equal("OUTSIDE_PROVING_ARCHIVES");
      }
    });

    it("the committed fixtures are exactly what the fixture library describes", function () {
      const archive = read(SAFE_ARCHIVE_REL);
      expect(gunzipSync(archive).equals(safeTar())).to.equal(true);
      expect(JSON.parse(read(SAFE_RECORD_REL).toString("utf8"))).to.deep.equal(syntheticRecord(archive, SAFE_FILES));
      const anchorFile = JSON.parse(read(SYNTHETIC_ANCHOR_REL).toString("utf8"));
      expect(anchorFile.synthetic).to.equal(true);
      expect(anchorFile.anchor).to.deep.equal(SYNTHETIC_ANCHOR);
      expect(SYNTHETIC_ANCHOR.verifyingKey.sha256).to.not.equal(productionAnchor(".").verifyingKey.sha256);
    });
  });

  describe("authoritative record locations", function () {
    it("is a regular .json file directly in evidence/zk/sp1-impl/proving-archives", function () {
      const repo = dirs.make();
      const dir = join(repo, PROVING_ARCHIVES_DIR);
      mkdirSync(join(dir, "nested"), { recursive: true });
      writeFileSync(join(dir, "v6.1.0-groth16.json"), "{}");
      writeFileSync(join(dir, "notes.txt"), "x");
      writeFileSync(join(dir, "nested", "r.json"), "{}");
      expect(authoritativeRecordError(join(dir, "v6.1.0-groth16.json"), repo)).to.equal(null);
      expect(authoritativeRecordError(join(dir, "notes.txt"), repo)).to.equal("NOT_JSON");
      expect(authoritativeRecordError(join(dir, "nested", "r.json"), repo)).to.equal("OUTSIDE_PROVING_ARCHIVES");
      expect(authoritativeRecordError(join(dir, "absent.json"), repo)).to.equal("ABSENT");
      expect(authoritativeRecordError(dir, repo)).to.equal("NOT_A_FILE");
      writeFileSync(join(repo, "elsewhere.json"), "{}");
      expect(authoritativeRecordError(join(repo, "elsewhere.json"), repo)).to.equal("OUTSIDE_PROVING_ARCHIVES");
    });
    it("is never a link, wherever it points", function () {
      const repo = dirs.make();
      const dir = join(repo, PROVING_ARCHIVES_DIR);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "real.json"), "{}");
      symlinkOrSkip(this, join(dir, "real.json"), join(dir, "link.json"), "file");
      expect(authoritativeRecordError(join(dir, "link.json"), repo)).to.equal("NOT_A_FILE");
    });
    it("is resolved through links: a proving-archives directory that is a link elsewhere holds no record", function () {
      const repo = dirs.make();
      const outside = dirs.make();
      writeFileSync(join(outside, "r.json"), "{}");
      mkdirSync(join(repo, PROVING_ARCHIVES_DIR, ".."), { recursive: true });
      symlinkOrSkip(this, outside, join(repo, PROVING_ARCHIVES_DIR), "dir");
      expect(authoritativeRecordError(join(repo, PROVING_ARCHIVES_DIR, "r.json"), repo)).to.equal(
        "OUTSIDE_PROVING_ARCHIVES",
      );
    });
  });

  describe("the upstream observation", function () {
    it("is bound to the host lockfile and its script, and measures exactly the pinned sp1/slop crates", function () {
      expect(upstreamObservationErrors(committedObservation(), ".")).to.deep.equal([]);
      const edits: [string, (o: any) => void, RegExp][] = [
        ["schema", (o) => (o.schema = "x"), /schema must be/],
        ["script", (o) => (o.tool.scriptSha256 = "0".repeat(64)), /not made by/],
        ["script path", (o) => (o.tool.script = "scripts/other.ts"), /not made by/],
        ["lockfile", (o) => (o.lockfile.sha256 = "0".repeat(64)), /measured another/],
        ["a crate", (o) => o.crates.pop(), /exactly the pinned/],
        ["a checksum", (o) => (o.crates[0].checksum = "0".repeat(64)), /exactly the pinned/],
        ["census", (o) => delete o.environment, /census is missing/],
        [
          "unreviewed non-literal read",
          (o) => o.nonLiteralEnvironmentReads.push("sp1-sdk/src/x.rs:1"),
          /non-literal name \(sp1-sdk\/src\/x\.rs:1\)/,
        ],
        ["no read list", (o) => delete o.nonLiteralEnvironmentReads, /non-literal name/],
      ];
      for (const [what, edit, want] of edits) {
        const o = clone(committedObservation());
        edit(o);
        expect(upstreamObservationErrors(o, ".").join("; "), what).to.match(want);
      }
    });

    it("records the readings the gate depends on", function () {
      const f = committedObservation().facts;
      expect(f.circuitVersion).to.equal("v6.1.0");
      expect(f.groth16Dir).to.deep.equal({
        env: "SP1_GROTH16_CIRCUIT_PATH",
        valueUsedVerbatim: true,
        joinsVersion: true,
        fallback: "~/.sp1/circuits/groth16",
      });
      expect(f.install).to.deep.equal({
        onlyWhenAbsent: true,
        verifiesDigest: false,
        extractFlags: "-Pxzf",
        url: "https://sp1-circuits.s3-us-east-2.amazonaws.com",
      });
      expect(f.circuitMode).to.deep.equal({ env: "SP1_CIRCUIT_MODE", devValue: "dev" });
      expect(f.prover).to.deep.equal({
        env: "SP1_PROVER",
        default: "cpu",
        modes: ["cpu", "cuda", "light", "mock", "network"],
      });
      expect(f.gnark).to.deep.equal({
        env: "SP1_GNARK_IMAGE",
        defaultImage: "ghcr.io/succinctlabs/sp1-gnark:v6.1.0",
        dockerRunArgs: ["run", "--rm"],
        pullFlag: false,
        mountSpec: "{src}:{dest}",
      });
    });
  });

  describe("reading the pinned sources", function () {
    it("reads the excerpts as the lane read the pinned crates", function () {
      expect(readUpstreamFacts(srcOf(SOURCES))).to.deep.equal({
        circuitVersion: "v6.1.0",
        groth16Dir: {
          env: "SP1_GROTH16_CIRCUIT_PATH",
          valueUsedVerbatim: true,
          joinsVersion: true,
          fallback: "~/.sp1/circuits/groth16",
        },
        install: {
          onlyWhenAbsent: true,
          verifiesDigest: false,
          extractFlags: "-Pxzf",
          url: "https://sp1-circuits.s3-us-east-2.amazonaws.com",
        },
        circuitMode: { env: "SP1_CIRCUIT_MODE", devValue: "dev" },
        prover: { env: "SP1_PROVER", default: "cpu", modes: ["cpu", "mock", "network"] },
        gnark: {
          env: "SP1_GNARK_IMAGE",
          defaultImage: "ghcr.io/succinctlabs/sp1-gnark:v6.1.0",
          dockerRunArgs: ["run", "--rm"],
          pullFlag: false,
          mountSpec: "{src}:{dest}",
        },
      });
    });
    it("notices a digest check, a pull flag, a moved version join and a changed install rule", function () {
      const variant = (crate: string, member: string, from: string, to: string) => {
        const s = clone(SOURCES);
        expect(s[crate][member].includes(from), from).to.equal(true);
        s[crate][member] = s[crate][member].replace(from, to);
        return readUpstreamFacts(srcOf(s));
      };
      expect(
        variant("sp1-prover", "src/build.rs", "client: &Client,", "client: &Client, sha256: [u8; 32],").install
          .verifiesDigest,
      ).to.equal(true);
      expect(
        variant("sp1-recursion-gnark-ffi", "src/ffi/docker.rs", '"--rm"', '"--rm", "--pull=never"').gnark.pullFlag,
      ).to.equal(true);
      expect(
        variant("sp1-prover", "src/build.rs", "Ok(base_path.join(SP1_CIRCUIT_VERSION))", "Ok(base_path)").groth16Dir
          .joinsVersion,
      ).to.equal(false);
      expect(
        variant("sp1-prover", "src/build.rs", "if build_dir.exists() {", "if true {").install.onlyWhenAbsent,
      ).to.equal(false);
    });
    it("stops when a reading no longer holds", function () {
      const broken: [string, string, string, string][] = [
        ["sp1-prover", "src/build.rs", "Ok(path) => PathBuf::from(path),", "Ok(path) => sanitize(path),"],
        ["sp1-prover", "src/build.rs", '"-Pxzf"', "EXTRACT"],
        ["sp1-prover", "src/build.rs", "pub async fn download_file(", "pub async fn fetch("],
        ["sp1-prover", "src/build.rs", '== "dev"', ".is_ok()"],
        ["sp1-sdk", "src/blocking/env/mod.rs", 'Err(_) => "cpu".to_string(),', "Err(_) => default(),"],
        ["sp1-sdk", "src/blocking/env/mod.rs", "_ => unreachable!(),", "_ => panic!(),"],
        ["sp1-recursion-gnark-ffi", "src/ffi/docker.rs", 'cmd.args(["run", "--rm"]);', "cmd.arg(RUN);"],
        ["sp1-recursion-gnark-ffi", "src/ffi/docker.rs", '.arg(format!("{src}:{dest}"));', ".arg(spec);"],
        ["sp1-recursion-gnark-ffi", "src/ffi/docker.rs", 'std::env::var("SP1_GNARK_IMAGE")', "image_from_config()"],
      ];
      for (const [crate, member, from, to] of broken) {
        const s = clone(SOURCES);
        expect(s[crate][member].includes(from), from).to.equal(true);
        s[crate][member] = s[crate][member].replace(from, to);
        expect(() => readUpstreamFacts(srcOf(s)), from).to.throw(/no longer reads as SP1-PA2A read it/);
      }
    });
    it("counts literal environment reads and flags non-literal ones", function () {
      const r = environmentReads(
        "c",
        new Map([
          [
            "src/a.rs",
            'let a = std::env::var("A_1"); let b = env::var_os("B");\nlet c = env::var(NAME);\nfor (k, v) in env::vars() {}',
          ],
          ["src/b.rs", 'env::var( "A_1" )'],
        ]),
      );
      expect(r.names).to.deep.equal(["A_1", "B"]);
      expect(r.nonLiteral).to.deep.equal(["c/src/a.rs:2", "c/src/a.rs:3"]);
    });
    it("measures checksum-verified crates from a cargo cache, offline", function () {
      const repo = dirs.make();
      const cargo = dirs.make();
      const cache = join(cargo, "registry", "cache", "index.crates.io-test");
      mkdirSync(cache, { recursive: true });
      mkdirSync(join(repo, "zkvm/host"), { recursive: true });
      let lock =
        'version = 4\n\n[[package]]\nname = "anyhow"\nversion = "1.0.0"\nsource = "registry"\nchecksum = "' +
        "a".repeat(64) +
        '"\n';
      for (const [name, files] of Object.entries(SOURCES)) {
        const crate = gz(tarBytes(Object.entries(files).map(([p, d]) => ({ name: `${name}-6.3.1/${p}`, data: d }))));
        writeFileSync(join(cache, `${name}-6.3.1.crate`), crate);
        lock += `\n[[package]]\nname = "${name}"\nversion = "6.3.1"\nsource = "registry"\nchecksum = "${sha256(crate)}"\n`;
      }
      writeFileSync(join(repo, "zkvm/host/Cargo.lock"), lock);
      const obs = measureUpstream({
        repoRoot: repo,
        cargoHome: cargo,
        host: "h",
        measuredAtUtc: "2026-01-01T00:00:00Z",
        tool: { script: UPSTREAM_SCRIPT_REL, scriptSha256: "s" },
      });
      expect(obs.crates.map((c) => [c.name, c.rustSources])).to.deep.equal([
        ["sp1-prover", 1],
        ["sp1-recursion-gnark-ffi", 1],
        ["sp1-sdk", 2],
      ]);
      expect(obs.environment).to.deep.equal({
        HOME: ["sp1-sdk"],
        NETWORK_PRIVATE_KEY: ["sp1-sdk"],
        SP1_CIRCUIT_MODE: ["sp1-prover"],
        SP1_GNARK_IMAGE: ["sp1-recursion-gnark-ffi"],
        SP1_GROTH16_CIRCUIT_PATH: ["sp1-prover"],
        SP1_PROVER: ["sp1-sdk"],
      });
      expect(obs.nonLiteralEnvironmentReads).to.deep.equal([]);
      expect(obs.facts.prover.modes).to.deep.equal(["cpu", "mock", "network"]);
      // A cached copy that is not the pinned crate is refused, as is a missing one.
      writeFileSync(join(cache, "sp1-sdk-6.3.1.crate"), "tampered");
      expect(() =>
        measureUpstream({
          repoRoot: repo,
          cargoHome: cargo,
          host: "h",
          measuredAtUtc: "x",
          tool: { script: "s", scriptSha256: "s" },
        }),
      ).to.throw(/is not the crate/);
      expect(() =>
        measureUpstream({
          repoRoot: repo,
          cargoHome: dirs.make(),
          host: "h",
          measuredAtUtc: "x",
          tool: { script: "s", scriptSha256: "s" },
        }),
      ).to.throw(/is not in the cargo cache/);
    });
  });

  describe("the gate covers what the pinned SP1 reads", function () {
    const anchor = () => productionAnchor(".");
    it("classifies variables as the gate treats them", function () {
      expect(envClass("SP1_GROTH16_CIRCUIT_PATH")).to.equal("FROZEN");
      expect(envClass("sp1_gnark_image")).to.equal("FROZEN");
      expect(envClass("DOCKER_CONTEXT")).to.equal("FROZEN");
      expect(envClass("SP1_CIRCUIT_MODE")).to.equal("REFUSED");
      expect(envClass("NETWORK_ANYTHING")).to.equal("REFUSED");
      expect(envClass("WITHOUT_VK_VERIFICATION")).to.equal("REFUSED");
      expect(envClass("HOME")).to.equal("PASSED");
      expect(envClass("SP1_WORKER_NUM_CORE_WORKERS")).to.equal("DROPPED");
      expect(envClass("LD_PRELOAD")).to.equal("DROPPED");
    });
    it("passes on the committed observation", function () {
      const o = committedObservation();
      expect(gateCoverageErrors(o.facts, o.environment, anchor())).to.deep.equal([]);
      for (const name of ["SP1_GROTH16_CIRCUIT_PATH", "SP1_GNARK_IMAGE", "SP1_PROVER"])
        expect(envClass(name)).to.equal("FROZEN");
      for (const name of [
        "SP1_CIRCUIT_MODE",
        "NETWORK_PRIVATE_KEY",
        "NETWORK_RPC_URL",
        "SKIP_SIMULATION",
        "WITHOUT_VK_VERIFICATION",
        "SP1_PLONK_CIRCUIT_PATH",
      ]) {
        expect(o.environment, name).to.have.property(name);
        expect(envClass(name), name).to.equal("REFUSED");
      }
    });
    it("fails when SP1 would select the circuit, image or prover through a variable the gate does not hold", function () {
      const edits: [string, (o: UpstreamObservation) => void, RegExp][] = [
        [
          "circuit dir",
          (o) => (o.facts.groth16Dir.env = "SP1_GROTH16_DIR"),
          /circuit directory is selected by SP1_GROTH16_DIR/,
        ],
        ["gnark", (o) => (o.facts.gnark.env = "SP1_GNARK"), /gnark image is selected by SP1_GNARK/],
        ["prover", (o) => (o.facts.prover.env = "SP1_BACKEND"), /prover mode is selected by SP1_BACKEND/],
        [
          "mode",
          (o) => (o.facts.circuitMode.env = "SP1_MODE"),
          /development circuit mode is selected by SP1_MODE, which the gate does not refuse/,
        ],
        ["no cpu", (o) => (o.facts.prover.modes = ["network"]), /no cpu mode/],
        [
          "no version join",
          (o) => (o.facts.groth16Dir.joinsVersion = false),
          /no longer reads <root>\/<circuit version>/,
        ],
        ["circuit", (o) => (o.facts.circuitVersion = "v6.2.0"), /circuit v6\.2\.0 is not the designated v6\.1\.0/],
        [
          "a passed variable SP1 reads",
          (o) => (o.environment.PATH = ["sp1-sdk"]),
          /passes PATH through, and the pinned SP1 reads it/,
        ],
      ];
      for (const [what, edit, want] of edits) {
        const o = clone(committedObservation());
        edit(o);
        expect(gateCoverageErrors(o.facts, o.environment, anchor()).join("; "), what).to.match(want);
      }
    });
  });

  describe("the AppleDouble and provenance policies, against the census they are derived from", function () {
    const census = () => JSON.parse(read(CENSUS_OBSERVATIONS_REL[0]).toString("utf8"));
    const adAt = (c: any, path: string) => c.appleDouble.find((r: any) => r.path === path);
    const entryAt = (c: any, path: string) => c.entries.find((e: any) => e.path === path);

    it("holds on both committed observations, which are one census", function () {
      expect(read(CENSUS_OBSERVATIONS_REL[0]).equals(read(CENSUS_OBSERVATIONS_REL[1]))).to.equal(true);
      expect(censusObservationErrors(".")).to.deep.equal([]);
      const c = census();
      expect(c.archive.sha256).to.equal("18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810");
      expect(c.appleDouble).to.have.length(8);
      expect(censusPolicyErrors(c)).to.deep.equal([]);
    });

    it("names every way the constants are not what the census observed", function () {
      const edits: [string, (c: any) => void, RegExp][] = [
        ["another schema", (c) => (c.schema = "x"), /a census must be/],
        [
          "another body",
          (c) => (adAt(c, "._groth16_pk.bin").sha256 = "0".repeat(64)),
          /APPLEDOUBLE_BODIES is not exactly/,
        ],
        ["another length", (c) => (adAt(c, "._groth16_pk.bin").size = 162), /APPLEDOUBLE_BODIES is not exactly/],
        [
          "a nested name",
          (c) => (adAt(c, "._groth16_pk.bin").path = "a/._groth16_pk.bin"),
          /APPLEDOUBLE_PATHS is not exactly/,
        ],
        ["a directory", (c) => (adAt(c, "._groth16_pk.bin").typeflag = "5"), /not a regular file/],
        ["an orphan", (c) => (adAt(c, "._groth16_pk.bin").companionFollows = false), /not followed by the entry/],
        ["the same path", (c) => (adAt(c, "._groth16_pk.bin").sameAsOther = ["x"]), /collides with x/],
        ["a case variant", (c) => (adAt(c, "._groth16_pk.bin").caseFoldSameAsOther = ["x"]), /collides with x/],
        ["a Windows alias", (c) => (adAt(c, "._groth16_pk.bin").windowsNameSameAsOther = ["x"]), /collides with x/],
        ["a parent", (c) => (adAt(c, "._groth16_pk.bin").parentOfOther = ["x"]), /collides with x/],
        ["a child", (c) => (adAt(c, "._groth16_pk.bin").otherIsParent = ["x"]), /collides with x/],
        [
          "a PAX header on an AppleDouble entry",
          (c) => entryAt(c, "./._groth16_pk.bin").pax.push({ key: "mtime", valueBytes: 1, valueSha256: "0" }),
          /has a PAX header/,
        ],
        [
          "an entry without the provenance record",
          (c) => (entryAt(c, "./groth16_witness.json").pax = []),
          /PROVENANCE_ENTRIES is not exactly/,
        ],
        [
          "the provenance record on another entry",
          (c) => (entryAt(c, "./groth16_witness.json").path = "./other.json"),
          /PROVENANCE_ENTRIES is not exactly/,
        ],
        ["the root as a file", (c) => (entryAt(c, "./").typeflag = "0"), /PROVENANCE_ENTRIES is not exactly/],
        [
          "another provenance value",
          (c) => (entryAt(c, "./groth16_pk.bin").pax.find((p: any) => p.key === PROVENANCE_PAX_KEY).valueSha256 = "0"),
          /carries another .* value than PROVENANCE_VALUE/,
        ],
        [
          "another provenance length",
          (c) => (entryAt(c, "./groth16_pk.bin").pax.find((p: any) => p.key === PROVENANCE_PAX_KEY).valueBytes = 12),
          /carries another .* value than PROVENANCE_VALUE/,
        ],
      ];
      for (const [what, edit, want] of edits) {
        const c = census();
        edit(c);
        const errors = censusPolicyErrors(c);
        expect(errors, what).to.have.length(1);
        expect(errors[0], what).to.match(want);
      }
    });

    it("refuses observations that are absent or are not one census", function () {
      const repo = dirs.make();
      mkdirSync(join(repo, "evidence/zk/sp1-impl/observations"), { recursive: true });
      expect(censusObservationErrors(repo)).to.deep.equal(["the census observations are not one census"]);
      writeFileSync(join(repo, CENSUS_OBSERVATIONS_REL[0]), read(CENSUS_OBSERVATIONS_REL[0]));
      expect(censusObservationErrors(repo)).to.deep.equal(["the census observations are not one census"]);
      const other = census();
      other.tar.entries += 1;
      writeFileSync(join(repo, CENSUS_OBSERVATIONS_REL[1]), `${JSON.stringify(other, null, 2)}\n`);
      expect(censusObservationErrors(repo)).to.deep.equal(["the census observations are not one census"]);
      // The same bytes with CRLF line ends (as an autocrlf checkout writes them) are one census, as committed.
      writeFileSync(
        join(repo, CENSUS_OBSERVATIONS_REL[1]),
        read(CENSUS_OBSERVATIONS_REL[0]).toString("utf8").replace(/\n/g, "\r\n"),
      );
      expect(censusObservationErrors(repo)).to.deep.equal([]);
      // The same census reformatted, in both files, is not the census tool's output.
      for (const rel of CENSUS_OBSERVATIONS_REL) writeFileSync(join(repo, rel), `${JSON.stringify(census())}\n`);
      expect(censusObservationErrors(repo)).to.deep.equal(["the census observations are not the census tool's output"]);
      expect(serializeCensus(census())).to.equal(read(CENSUS_OBSERVATIONS_REL[0]).toString("utf8"));
    });
  });

  describe("the archive record's JSON Schema", function () {
    const schema = JSON.parse(read(ARCHIVE_JSON_SCHEMA_REL).toString("utf8"));
    it("names the validator's fields, level by level, and forbids others", function () {
      const at = (path: string[]) => path.reduce((s, k) => (k === "[]" ? s.items : s.properties[k]), schema);
      const levels: [string[], readonly string[]][] = [
        [[], RECORD_FIELDS.record],
        [["subject"], RECORD_FIELDS.subject],
        [["subject", "verifier"], RECORD_FIELDS.verifier],
        [["subject", "verifyingKey"], RECORD_FIELDS.verifyingKey],
        [["archive"], RECORD_FIELDS.archive],
        [["acquisitions", "[]"], RECORD_FIELDS.acquisition],
        [["members", "[]"], RECORD_FIELDS.member],
        [["metadata", "[]"], RECORD_FIELDS.metadata],
        [["gnark"], RECORD_FIELDS.gnark],
        [["gnark", "observation"], RECORD_FIELDS.gnarkObservation],
        [["mirrors", "[]"], RECORD_FIELDS.mirror],
      ];
      for (const [path, fields] of levels) {
        const s = at(path);
        expect(s.required, path.join(".")).to.deep.equal([...fields]);
        expect(Object.keys(s.properties), path.join(".")).to.deep.equal([...fields]);
        expect(s.additionalProperties, path.join(".")).to.equal(false);
      }
      expect(schema.$id).to.equal("walletwall.sp1-proving-archive.v2");
      expect(schema.properties.schema.const).to.equal(ARCHIVE_RECORD_SCHEMA);
      expect(ARCHIVE_RECORD_SCHEMA).to.equal("walletwall.sp1-proving-archive.v2");
      expect(schema.properties.acquisitions.minItems).to.equal(2);
      expect(schema.properties.mirrors.minItems).to.equal(2);
    });
  });

  describe("the CLIs refuse what this lane cannot authorize", function () {
    const tsx = (script: string, args: string[]) =>
      spawnSync(process.execPath, ["--import", "tsx", script, ...args], { encoding: "utf8", timeout: 120_000 });
    it("install and prove refuse a fixture record as not authoritative; inspect refuses the synthetic key for d1", function () {
      this.timeout(240_000);
      if (!insideGit) this.skip(); // the anchor counts only as committed evidence of a git checkout
      const root = dirs.make();
      const install = tsx("scripts/sp1-circuit-install.ts", [
        "--archive",
        SAFE_ARCHIVE_REL,
        "--record",
        SAFE_RECORD_REL,
        "--destination-root",
        root,
      ]);
      expect(install.status).to.equal(1);
      expect(install.stderr).to.include("RECORD_NOT_AUTHORITATIVE (OUTSIDE_PROVING_ARCHIVES)");
      const prove = tsx("scripts/sp1-prove-archive-only.ts", [
        "--record",
        SAFE_RECORD_REL,
        "--circuit-root",
        root,
        "--host",
        root,
        "--inputs",
        root,
      ]);
      expect(prove.status).to.equal(1);
      expect(prove.stderr).to.include("RECORD_NOT_AUTHORITATIVE (OUTSIDE_PROVING_ARCHIVES)");
      const inspect = tsx("scripts/sp1-circuit-archive-inspect.ts", ["--archive", SAFE_ARCHIVE_REL]);
      expect(inspect.status).to.equal(1);
      expect(inspect.stderr).to.include("VK_MISMATCH");
      const withRecord = tsx("scripts/sp1-circuit-archive-inspect.ts", [
        "--archive",
        SAFE_ARCHIVE_REL,
        "--record",
        SAFE_RECORD_REL,
      ]);
      expect(withRecord.status).to.equal(1);
      expect(withRecord.stderr).to.include("RECORD_INVALID (SUBJECT_MISMATCH)");
    });
    it("the upstream measurement writes only the developer-workstation observation", function () {
      this.timeout(120_000);
      const r = tsx("scripts/measure-sp1-circuit-upstream.ts", ["--cargo-home", dirs.make(), "--host", "elsewhere"]);
      expect(r.status).to.equal(1);
      expect(r.stderr).to.include(UPSTREAM_OBSERVATION_REL);
    });
    it("read their anchor from the checkout they live in, never the working directory", function () {
      this.timeout(120_000);
      // A crafted working directory with its own evidence and a "production" record: the review's attack.
      const fake = dirs.make();
      cpSync(resolve("evidence/zk/sp1/designations"), join(fake, "evidence/zk/sp1/designations"), { recursive: true });
      cpSync(resolve(PROVING_AVAILABILITY_REL), join(fake, PROVING_AVAILABILITY_REL));
      mkdirSync(join(fake, PROVING_ARCHIVES_DIR), { recursive: true });
      const forged = join(fake, PROVING_ARCHIVES_DIR, "v6.1.0-groth16.json");
      cpSync(resolve(SAFE_RECORD_REL), forged);
      const cli = resolve("node_modules/tsx/dist/cli.mjs");
      const r = spawnSync(
        process.execPath,
        [
          cli,
          resolve("scripts/sp1-circuit-install.ts"),
          "--archive",
          resolve(SAFE_ARCHIVE_REL),
          "--record",
          forged,
          "--destination-root",
          dirs.make(),
        ],
        { cwd: fake, encoding: "utf8", timeout: 120_000 },
      );
      expect(r.status).to.equal(1);
      expect(r.stderr).to.include("RECORD_NOT_AUTHORITATIVE (OUTSIDE_PROVING_ARCHIVES)");
      const root = dirs.make();
      const prove = spawnSync(
        process.execPath,
        [
          cli,
          resolve("scripts/sp1-prove-archive-only.ts"),
          "--record",
          forged,
          "--circuit-root",
          root,
          "--host",
          root,
          "--inputs",
          root,
        ],
        { cwd: fake, encoding: "utf8", timeout: 120_000 },
      );
      expect(prove.status).to.equal(1);
      expect(prove.stderr).to.include("RECORD_NOT_AUTHORITATIVE (OUTSIDE_PROVING_ARCHIVES)");
      if (!insideGit) return;
      // Inspection reads d1 from this checkout's committed evidence, so the synthetic key is refused, not accepted.
      const inspect = spawnSync(
        process.execPath,
        [cli, resolve("scripts/sp1-circuit-archive-inspect.ts"), "--archive", resolve(SAFE_ARCHIVE_REL)],
        { cwd: fake, encoding: "utf8", timeout: 120_000 },
      );
      expect(inspect.status).to.equal(1);
      expect(inspect.stderr).to.include("VK_MISMATCH");
    });
  });

  describe("committed evidence", function () {
    const git = (cwd: string, ...args: string[]) => {
      const r = spawnSync("git", args, { cwd, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout;
    };
    function repo() {
      const d = dirs.make();
      git(d, "init", "-q");
      git(d, "config", "user.email", "test@example.invalid");
      git(d, "config", "user.name", "test");
      git(d, "config", "commit.gpgsign", "false");
      mkdirSync(join(d, PROVING_ARCHIVES_DIR), { recursive: true });
      mkdirSync(join(d, "evidence/zk/sp1/designations"), { recursive: true });
      writeFileSync(join(d, "evidence/zk/sp1/designations/a.json"), "{}\n");
      writeFileSync(join(d, PROVING_ARCHIVES_DIR, "r.json"), '{"record":1}\n');
      git(d, "add", "-A");
      git(d, "commit", "-q", "-m", "evidence");
      return d;
    }
    it("is exactly what HEAD commits: modified, untracked or unknown paths are refused", function () {
      this.timeout(60_000);
      const d = repo();
      const dir = "evidence/zk/sp1/designations";
      expect(uncommittedEvidenceError([dir], d)).to.equal(null);
      writeFileSync(join(d, dir, "b.json"), "{}\n");
      expect(uncommittedEvidenceError([dir], d)).to.match(/^UNCOMMITTED \?\? /);
      rmSync(join(d, dir, "b.json"));
      writeFileSync(join(d, dir, "a.json"), '{"changed":true}\n');
      expect(uncommittedEvidenceError([dir], d)).to.match(/^UNCOMMITTED M /);
      expect(uncommittedEvidenceError(["evidence/absent.json"], d)).to.equal("UNTRACKED evidence/absent.json");
      expect(uncommittedEvidenceError([dir], dirs.make())).to.equal("NOT_A_GIT_CHECKOUT");
    });
    it("a production record counts only as committed", async function () {
      this.timeout(60_000);
      const d = repo();
      const r = join(d, PROVING_ARCHIVES_DIR, "r.json");
      expect(committedProductionRecord(r, d)).to.deep.equal({ record: 1 });
      writeFileSync(r, '{"record":2}\n');
      expect(await refusalOf(() => committedProductionRecord(r, d))).to.equal("RECORD_NOT_AUTHORITATIVE (UNCOMMITTED)");
      const fresh = join(d, PROVING_ARCHIVES_DIR, "new.json");
      writeFileSync(fresh, "{}\n");
      expect(await refusalOf(() => committedProductionRecord(fresh, d))).to.equal(
        "RECORD_NOT_AUTHORITATIVE (UNTRACKED)",
      );
      expect(await refusalOf(() => committedProductionRecord(join(d, "elsewhere.json"), d))).to.equal(
        "RECORD_NOT_AUTHORITATIVE (ABSENT)",
      );
    });
    it("the production anchor's evidence counts only as committed, and only as a valid designation set", async function () {
      this.timeout(60_000);
      if (!insideGit) this.skip();
      expect(await refusalOf(() => committedProductionAnchor(dirs.make()))).to.equal(
        "EVIDENCE_NOT_COMMITTED (NOT_A_GIT_CHECKOUT)",
      );
      expect(committedProductionAnchor(resolve("."))).to.deep.equal(productionAnchor("."));
      const fake = dirs.make();
      cpSync(resolve("evidence/zk/sp1/designations"), join(fake, "evidence/zk/sp1/designations"), { recursive: true });
      cpSync(resolve(PROVING_AVAILABILITY_REL), join(fake, PROVING_AVAILABILITY_REL));
      const d1 = JSON.parse(read("evidence/zk/sp1/designations/mldsa65-withdrawal-d1.json").toString("utf8"));
      const d2 = { ...d1, id: "mldsa65-withdrawal-d2", sequence: 2, soundness: "ESTABLISHED" };
      writeFileSync(join(fake, "evidence/zk/sp1/designations/mldsa65-withdrawal-d2.json"), JSON.stringify(d2));
      expect(() => productionAnchor(fake)).to.throw(/not a valid set/);
    });
  });

  describe("CI", function () {
    const pkg = JSON.parse(read("package.json").toString("utf8"));
    const ci = read(".github/workflows/ci.yml")
      .toString("utf8")
      .split("\n")
      .filter((l) => !/^\s*#/.test(l))
      .join("\n");
    it("runs the deterministic tooling validator in Build, lint & test, before the test suite", function () {
      expect(pkg.scripts["validate:sp1-circuit-tooling"]).to.equal(
        "tsx scripts/generate-sp1-circuit-tooling.ts --validate",
      );
      const job = ci.slice(ci.indexOf("  build-test:"), ci.indexOf("  zkvm-guest:"));
      expect(job).to.include("npm run validate:sp1-circuit-tooling");
      expect(job.indexOf("npm run validate:sp1-circuit-tooling")).to.be.lessThan(job.indexOf("run: npm test"));
    });
    it("names every tooling command, none of which downloads, pulls or proves in CI", function () {
      for (const s of [
        "sp1:circuit-archive:inspect",
        "sp1:circuit-archive:census",
        "sp1:circuit-install",
        "sp1:prove:archive-only",
        "sp1:measure-circuit-upstream",
        "sp1:circuit-tooling",
      ]) {
        expect(pkg.scripts, s).to.have.property(s);
        expect(ci.includes(`npm run ${s} `) || ci.includes(`npm run ${s}\n`), `${s} is not a CI step`).to.equal(false);
      }
      expect(ci.includes("docker pull")).to.equal(false);
      expect(ci.includes("sp1-circuits.s3")).to.equal(false);
    });
  });

  describe("the owner-facing page", function () {
    const doc = read("docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md").toString("utf8");
    it("keeps the four states apart and proving availability unchanged", function () {
      for (const s of STATES) expect(doc, s.state).to.include(s.state);
      expect(doc).to.include("4. Production binding established");
      expect(doc).to.include("`PROVING_AVAILABILITY = OWNER_DOWNLOAD_REQUIRED`");
      expect(doc).to.include("Research prototype. Not audited. Testnet/local only. Do not use real funds.");
    });
    it("claims only that the gate can refuse the downloader, not that proving never exercises it", function () {
      expect(doc).to.include(
        "WalletWall has a gate capable of refusing the built-in circuit downloader\n  once verified artifacts exist.",
      );
      expect(doc).to.include('It is not yet "WalletWall proving never exercises the downloader"');
    });
  });

  describe("git keeps the synthetic archive and refuses a real one", function () {
    /** The rule the repository's .gitignore applies to `path` (null: none), read with -v -n, never the exit code. */
    const rule = (path: string): string | null => {
      const r = spawnSync("git", ["check-ignore", "--no-index", "-v", "-n", path], { encoding: "utf8" });
      const [source] = r.stdout.split("\t");
      return source === "::" || source === "" ? null : source.split(":").slice(2).join(":");
    };
    before(function () {
      if (spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { encoding: "utf8" }).stdout.trim() !== "true") {
        this.skip();
      }
    });
    it("tracks the committed synthetic archive (the *.tar.gz rule would silently drop it)", function () {
      expect(rule(SAFE_ARCHIVE_REL)).to.equal("!test/fixtures/sp1-proving-archives/synthetic-*.tar.gz");
      const tracked = spawnSync("git", ["ls-files", "--error-unmatch", SAFE_ARCHIVE_REL], { encoding: "utf8" });
      expect(tracked.status, "the synthetic archive is committed").to.equal(0);
    });
    it("still ignores a real circuit archive everywhere, the fixtures directory and proving-archives included", function () {
      for (const p of [
        "v6.1.0-groth16.tar.gz",
        `${FIXTURES_DIR}/v6.1.0-groth16.tar.gz`,
        `${PROVING_ARCHIVES_DIR}/v6.1.0-groth16.tar.gz`,
        `${FIXTURES_DIR}/synthetic-safe.tar`,
      ]) {
        expect(rule(p), p).to.match(/^\*\.tar(\.gz)?$/);
      }
    });
  });
});
