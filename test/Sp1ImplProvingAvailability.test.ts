/**
 * SP1 implementation lane: proving availability (SP1-TD1 finding TD1-N9; scripts/lib/sp1-proving-availability.ts).
 *
 * The 2-day rotation protects a PqOnly user only while they can prove, and Groth16 proving for circuit v6.1.0 needs
 * Succinct's circuit artifacts. What is known offline is measured from the crates zkvm/host/Cargo.lock pins (the
 * expected groth16_vk.bin, where the pinned prover fetches the artifacts and how it uses them), what is absent is
 * measured on the proving host, and the status is derived from both: no WalletWall archive and no local copy is
 * OWNER_DOWNLOAD_REQUIRED. Upstream hosting is never availability, and nothing here downloads.
 */
import { expect } from "chai";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import { readDesignations } from "../scripts/lib/sp1-designation";
import {
  HOST_LOCK_REL,
  PROVING_ARCHIVES_DIR,
  PROVING_ARTIFACTS_OBSERVATION_REL,
  PROVING_AVAILABILITY_REL,
  archiveEvidenceFromRepo,
  archiveRecordsIn,
  gnarkFeaturesOf,
  lockedCrates,
  measureProvingArtifacts,
  provingArtifactsObservationErrors,
  provingAvailabilityErrors,
  provingAvailabilityStatus,
  readTarMembers,
  type ProvingArtifactsObservation,
} from "../scripts/lib/sp1-proving-availability";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

/** A minimal tar writer: ustar or GNU headers, GNU long names, so the reader is tested on archives it did not write. */
function tarHeader(name: string, size: number, type: string, gnu: boolean): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, "latin1");
  h.write("0000644\0", 100, "latin1");
  h.write("0000000\0", 108, "latin1");
  h.write("0000000\0", 116, "latin1");
  h.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "latin1");
  h.write("00000000000\0", 136, "latin1");
  h.write(type, 156, "latin1");
  h.write(gnu ? "ustar  \0" : "ustar\u000000", 257, "latin1");
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return h;
}
const pad = (b: Buffer) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
function tarGz(files: [string, Buffer | string][], gnu = true): Buffer {
  const parts: Buffer[] = [];
  for (const [name, content] of files) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    if (name.length > 100) {
      const long = Buffer.from(`${name}\0`);
      parts.push(tarHeader("././@LongLink", long.length, "L", true), pad(long));
    }
    parts.push(tarHeader(name, data.length, "0", gnu), pad(data));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

/** Excerpts shaped like the pinned crates' sources: what the lane read, in the form the measurement must find. */
const PROVER_BUILD_RS = `
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
    let build_dir = groth16_circuit_artifacts_dir()?;
    if build_dir.exists() {
        tracing::info!("exists");
    } else {
        install_circuit_artifacts(build_dir.clone(), artifacts_type).await?;
    }
    Ok(build_dir)
}

pub async fn install_circuit_artifacts(build_dir: PathBuf, artifacts_type: &str) -> Result<()> {
    let download_url =
        format!("{CIRCUIT_ARTIFACTS_URL_BASE}/{SP1_CIRCUIT_VERSION}-{artifacts_type}.tar.gz");
    download_file(&client, &download_url, &mut file).await?;
    let res =
        Command::new("tar").args(["-Pxzf", tar_path_str, "-C", build_dir_str]).output().await?;
    Ok(())
}

pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<()> {
    let res = client.get(url).send().await?;
    Ok(())
}
`;
const GNARK_DOCKER_RS = `
fn get_docker_image() -> String {
    std::env::var("SP1_GNARK_IMAGE")
        .unwrap_or_else(|_| format!("ghcr.io/succinctlabs/sp1-gnark:{SP1_CIRCUIT_VERSION}"))
}
`;
const GNARK_GROTH16_RS = `
    pub fn get_vkey_hash(build_dir: &Path) -> [u8; 32] {
        let vkey_path = build_dir.join("groth16_vk.bin");
        let vk_bin_bytes = std::fs::read(vkey_path).unwrap();
        Sha256::digest(vk_bin_bytes).into()
    }
`;
const GNARK_SP1_GO = `
var constraintsJsonFile string = "constraints.json"
var groth16CircuitPath string = "groth16_circuit.bin"
var groth16VkPath string = "groth16_vk.bin"
var groth16PkPath string = "groth16_pk.bin"
`;
const GNARK_PROVE_GO = `
func ProveGroth16(dataDir string, witnessPath string) Proof {
\tos.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
\tr1csFile, err := os.Open(dataDir + "/" + groth16CircuitPath)
\tpkFile, err := os.Open(dataDir + "/" + groth16PkPath)
\tdata, err := os.ReadFile(witnessPath)
}
`;
const VK = Buffer.from("a synthetic Groth16 verifying key");
const TREE = "sp1-recursion-gnark-ffi v6.3.1\n└── sp1-prover v6.3.1\n    └── sp1-sdk v6.3.1\n";

interface FakeHost {
  cargoHome: string;
  home: string;
  repo: string;
}

/** A proving host's cargo cache and home, and a repository whose host lockfile pins the crates written. */
function fakeHost(over: { buildRs?: string; proverVersion?: string; corruptCrate?: string } = {}): FakeHost {
  const root = mkdtempSync(join(tmpdir(), "sp1-proving-"));
  const cache = join(root, "cargo", "registry", "cache", "index.crates.io-0000000000000000");
  mkdirSync(cache, { recursive: true });
  mkdirSync(join(root, "home"), { recursive: true });
  mkdirSync(join(root, "repo", "zkvm", "host"), { recursive: true });
  const crates: [string, [string, Buffer | string][]][] = [
    [
      "sp1-prover",
      [
        ["SP1_CIRCUIT_VERSION", over.proverVersion ?? "v6.1.0"],
        ["src/build.rs", over.buildRs ?? PROVER_BUILD_RS],
      ],
    ],
    [
      "sp1-recursion-gnark-ffi",
      [
        ["assets/SP1_CIRCUIT_VERSION", "v6.1.0"],
        ["src/ffi/docker.rs", GNARK_DOCKER_RS],
        ["src/groth16_bn254.rs", GNARK_GROTH16_RS],
        ["go/sp1/sp1.go", GNARK_SP1_GO],
        ["go/sp1/prove_groth16.go", GNARK_PROVE_GO],
      ],
    ],
    ["sp1-verifier", [["vk-artifacts/groth16_vk.bin", VK]]],
  ];
  let lock = "version = 4\n";
  for (const [name, members] of crates) {
    const bytes = tarGz(members.map(([m, c]) => [`${name}-6.3.1/${m}`, c]));
    writeFileSync(
      join(cache, `${name}-6.3.1.crate`),
      over.corruptCrate === name ? Buffer.concat([bytes, Buffer.from([0])]) : bytes,
    );
    lock += `\n[[package]]\nname = "${name}"\nversion = "6.3.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${sha256(bytes)}"\n`;
  }
  writeFileSync(join(root, "repo", HOST_LOCK_REL), lock);
  return { cargoHome: join(root, "cargo"), home: join(root, "home"), repo: join(root, "repo") };
}

function measure(h: FakeHost, tree = TREE) {
  return measureProvingArtifacts({
    repoRoot: h.repo,
    cargoHome: h.cargoHome,
    home: h.home,
    hostId: "test-host",
    cargoTree: { command: "cargo tree --offline --locked -e features -i sp1-recursion-gnark-ffi", output: tree },
    localImages: () => [],
    measuredAtUtc: "2026-10-16T00:00:00Z",
    tool: { script: "test", scriptSha256: "00" },
  });
}

describe("SP1 implementation lane — proving availability (TD1-N9)", function () {
  const designations = () => readDesignations(".");
  const committedObservation = () =>
    JSON.parse(readFileSync(PROVING_ARTIFACTS_OBSERVATION_REL, "utf8")) as ProvingArtifactsObservation;

  it("reads a crate's members from its gzip'd tar, GNU long names included; refuses a corrupt or ambiguous archive", function () {
    const long = `sp1-verifier-6.3.1/${"d/".repeat(60)}groth16_vk.bin`;
    const members = readTarMembers(
      tarGz([
        ["a/x.txt", "one"],
        [long, VK],
      ]),
    );
    expect(members.get("a/x.txt")!.toString()).to.equal("one");
    expect(sha256(members.get(long)!)).to.equal(sha256(VK));
    expect(
      readTarMembers(tarGz([["a/y.txt", "two"]], false))
        .get("a/y.txt")!
        .toString(),
    ).to.equal("two");
    const raw = Buffer.concat([tarHeader("a/z.txt", 3, "0", true), pad(Buffer.from("abc")), Buffer.alloc(1024)]);
    raw[0] ^= 1; // the checksum no longer matches the header
    assert.throws(() => readTarMembers(gzipSync(raw)), /checksum/);
    const cut = Buffer.concat([tarHeader("a/z.txt", 900, "0", true), Buffer.from("abc")]);
    assert.throws(() => readTarMembers(gzipSync(cut)), /truncated/);
    assert.throws(
      () =>
        readTarMembers(
          tarGz([
            ["a/x.txt", "one"],
            ["a/x.txt", "two"],
          ]),
        ),
      /twice/,
    );
  });

  it("measures only the crates the host lockfile pins: a cached crate with other bytes is refused", function () {
    const obs = measure(fakeHost());
    expect(obs.crates.map((c) => c.name)).to.deep.equal(["sp1-prover", "sp1-recursion-gnark-ffi", "sp1-verifier"]);
    for (const c of obs.crates) expect(c.crateSha256).to.equal(c.lockChecksum);
    expect(obs.source.groth16Vk).to.deep.equal({ sha256: sha256(VK), bytes: VK.length });
    assert.throws(() => measure(fakeHost({ corruptCrate: "sp1-verifier" })), /not the crate .*Cargo\.lock pins/);
    const locked = lockedCrates(readFileSync(join(fakeHost().repo, HOST_LOCK_REL), "utf8"));
    expect(locked.get("sp1-verifier")).to.have.property("version", "6.3.1");
  });

  it("reads the pinned prover's source as this lane read it; bytes that no longer read that way fail the measurement", function () {
    const s = measure(fakeHost()).source;
    expect(s).to.deep.include({
      circuitVersion: "v6.1.0",
      artifactUrl: "https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.1.0-groth16.tar.gz",
      groth16DirEnv: "SP1_GROTH16_CIRCUIT_PATH",
      groth16DefaultDir: "~/.sp1/circuits/groth16/v6.1.0",
      circuitModeEnv: "SP1_CIRCUIT_MODE",
      extractFlags: "-Pxzf",
      reusesExistingDir: true,
      downloadVerifiesHash: false,
      gnarkImageEnv: "SP1_GNARK_IMAGE",
      gnarkImage: "ghcr.io/succinctlabs/sp1-gnark:v6.1.0",
      groth16VkFile: "groth16_vk.bin",
    });
    expect(s.groth16ProveReads).to.deep.equal(["constraints.json", "groth16_circuit.bin", "groth16_pk.bin"]);
    // A download that checks a digest is a different prover: the lane's reading no longer applies.
    const hashing = PROVER_BUILD_RS.replace(
      "download_file(&client",
      "verify_sha256(&file)?;\n    download_file(&client",
    );
    expect(measure(fakeHost({ buildRs: hashing })).source.downloadVerifiesHash).to.equal(true);
    const moved = PROVER_BUILD_RS.replace("CIRCUIT_ARTIFACTS_URL_BASE: &str", "CIRCUIT_ARTIFACTS_URL: &str");
    assert.throws(() => measure(fakeHost({ buildRs: moved })), /no longer reads/);
    assert.throws(() => measure(fakeHost({ proverVersion: "v6.1.1" })), /circuit version/);
  });

  it("measures the local install, absent and present, and the gnark backend from the inverted feature tree", function () {
    const h = fakeHost();
    expect(measure(h).local).to.deep.include({ circuitsRootPresent: false, groth16DirPresent: false });
    mkdirSync(join(h.home, ".sp1", "circuits", "groth16", "v6.1.0"), { recursive: true });
    expect(measure(h).local).to.deep.include({ circuitsRootPresent: true, groth16DirPresent: true });
    expect(measure(h).gnark).to.deep.include({ backend: "docker", features: [] });
    const native = `${TREE}├── sp1-recursion-gnark-ffi feature "native"\n│   └── sp1-prover feature "native-gnark"\n`;
    expect(gnarkFeaturesOf(native, "6.3.1")).to.deep.equal(["native"]);
    expect(measure(h, native).gnark.backend).to.equal("native");
    assert.throws(() => gnarkFeaturesOf("sp1-prover v6.3.1\n", "6.3.1"), /inverted feature tree/);
  });

  it("the committed observation and record re-derive, and the status is OWNER_DOWNLOAD_REQUIRED", function () {
    // The title is the implementation receipt's citation (SP1-IMPL derived OWNER_DOWNLOAD_REQUIRED, and the receipt is
    // historical, never restamped). What it pins: with no archive record the status is OWNER_DOWNLOAD_REQUIRED, and the
    // committed record is exactly what the committed evidence derives, whichever state SP1-PA2B's archive evidence holds.
    expect(provingAvailabilityErrors(".")).to.deep.equal([]);
    const record = JSON.parse(readFileSync(PROVING_AVAILABILITY_REL, "utf8"));
    const obs = committedObservation();
    expect(provingAvailabilityStatus(obs, [])).to.equal("OWNER_DOWNLOAD_REQUIRED");
    const records = archiveRecordsIn(".");
    const evidence = archiveEvidenceFromRepo(".", obs, designations());
    const status = provingAvailabilityStatus(obs, records, evidence);
    expect(record.status).to.equal(status);
    expect(status).to.equal(records.length === 0 ? "OWNER_DOWNLOAD_REQUIRED" : "ARCHIVED_VERIFIED_UNEXERCISED");
    expect(record.selfHostedPath.exercised).to.equal(false);
    expect(record.expectedArtifacts.tarball.sha256).to.equal(
      records.length === 0 ? null : evidence?.record?.archive.sha256,
    );
  });

  it("the expected groth16_vk.bin is the designated VERIFIER_HASH and the wrapper's SP1_VERIFIER_HASH", function () {
    const obs = committedObservation();
    const build = JSON.parse(readFileSync("evidence/zk/sp1/wrapper-builds/zkmldsa-verifier-b1.json", "utf8"));
    const td1 = JSON.parse(readFileSync("evidence/zk/sp1-td1/decision-receipt.json", "utf8"));
    for (const expected of [
      designations()[0].verifier.verifierHash,
      build.pins.sp1VerifierHash,
      td1.trustTarget.verifierHash,
    ]) {
      expect(`0x${obs.source.groth16Vk.sha256}`).to.equal(expected);
    }
    expect(obs.source.circuitVersion).to.equal(designations()[0].verifier.version);
  });

  it("refuses an observation whose verifying key, crate digests, circuit version, feature tree or script drift", function () {
    const ds = designations();
    const errorsOf = (mutate: (o: ProvingArtifactsObservation) => void) => {
      const o = structuredClone(committedObservation());
      mutate(o);
      return provingArtifactsObservationErrors(o, ds, ".").join("\n");
    };
    expect(errorsOf(() => undefined)).to.equal("");
    expect(errorsOf((o) => (o.source.groth16Vk.sha256 = "00".repeat(32)))).to.match(/VERIFIER_HASH/);
    expect(errorsOf((o) => (o.crates[2].crateSha256 = "00".repeat(32)))).to.match(/sp1-verifier.*lockfile/);
    expect(errorsOf((o) => (o.source.circuitVersion = "v6.0.0"))).to.match(/circuit version/);
    expect(errorsOf((o) => (o.gnark.output += 'sp1-recursion-gnark-ffi feature "native"\n'))).to.match(/feature tree/);
    expect(errorsOf((o) => (o.tool.scriptSha256 = "00".repeat(32)))).to.match(/re-measure/);
    expect(errorsOf((o) => (o.local.groth16DirPresent = "no" as never))).to.match(/local/);
  });

  it("a WalletWall archive record is refused until a lane validates it; a local copy is not availability", function () {
    const obs = committedObservation();
    const present = { ...obs, local: { ...obs.local, groth16DirPresent: true } };
    expect(provingAvailabilityStatus(present, [])).to.equal("LOCAL_COPY_NOT_ARCHIVED");
    const repo = mkdtempSync(join(tmpdir(), "sp1-archives-"));
    mkdirSync(join(repo, PROVING_ARCHIVES_DIR), { recursive: true });
    writeFileSync(join(repo, PROVING_ARCHIVES_DIR, "v6.1.0-groth16.json"), "{}");
    const records = archiveRecordsIn(repo);
    expect(records).to.deep.equal([`${PROVING_ARCHIVES_DIR}/v6.1.0-groth16.json`]);
    // A file in the archive directory is a record only as the acquisition evidence accepts it (SP1-PA2B): with no
    // judged evidence, or refused evidence, the status is not derived at all, never "no record".
    assert.throws(() => provingAvailabilityStatus(obs, records), /not an accepted production archive record/);
    const refused = { records, record: null, observations: [], errors: ["MIRRORS_MISSING: one mirror"] };
    assert.throws(() => provingAvailabilityStatus(obs, records, refused), /MIRRORS_MISSING/);
    // Without a record, no input derives availability: only the two unestablished states exist.
    for (const o of [obs, present])
      expect(["OWNER_DOWNLOAD_REQUIRED", "LOCAL_COPY_NOT_ARCHIVED"]).to.include(provingAvailabilityStatus(o, []));
  });
});
