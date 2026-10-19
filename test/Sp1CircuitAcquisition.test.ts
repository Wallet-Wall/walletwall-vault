/**
 * SP1-PA2B: the acquisition observations, their agreement, the derived archive record and the state the committed
 * evidence derives (scripts/lib/sp1-circuit-acquisition.ts). Everything here is synthetic: observations made for the
 * synthetic anchor, a fake registry, a temporary git repository. Offline: no network, no archive, no docker.
 *
 * The rule under test: a record is derived from measurements and accepted only when every fact holds; each
 * production-only requirement (two distinct hosts that agree, the inspection and census identical on both, the tag
 * resolved to one immutable digest on both, two distinct WalletWall mirrors re-read byte for byte, the record byte
 * for byte what the observations derive, all of it committed) can fail on its own, and a failure is never read as
 * "no record".
 */
import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  ACQUISITION_OBSERVATIONS_REL,
  ACQUISITION_SCHEMA,
  ACQUISITION_SCRIPT_REL,
  CENSUS_OBSERVATIONS_REL,
  DOCKER_MANIFEST_LIST,
  LINUX_AMD64,
  MIRROR_SCHEMA,
  MIRROR_SCRIPT_REL,
  OBSERVATIONS_DIR,
  OCI_INDEX,
  OCI_MANIFEST,
  REGISTRY_METHOD,
  acquisitionErrors,
  acquisitionExpectations,
  acquisitionObservationErrors,
  anchorFromDesignation,
  archiveEvidenceState,
  deriveArchiveRecord,
  mirrorObservationErrors,
  mirrorObservationsIn,
  normalizedLocation,
  parseTaggedRef,
  productionArchiveEvidence,
  productionRecordRel,
  resolveImageTag,
  serializeJson,
  type AcquisitionExpectations,
  type AcquisitionObservation,
  type ArchiveEvidence,
  type Fetch,
  type MirrorObservation,
} from "../scripts/lib/sp1-circuit-acquisition";
import {
  AGREES,
  PROVENANCE_ENTRIES,
  PROVENANCE_PAX_KEY,
  PROVING_ARCHIVES_DIR,
  VK_FILE,
  archiveRecordErrors,
  archiveRecordsIn,
  type ArchiveRecord,
} from "../scripts/lib/sp1-circuit-archive";
import {
  SYNTHETIC_ANCHOR,
  UPSTREAM_SHAPED_FILES,
  appleDoubleMetadata,
  membersOf,
} from "../scripts/lib/sp1-circuit-fixtures";
import {
  availabilityStatusesFor,
  pinnedGnarkImage,
  productionAnchor,
  toolingState,
} from "../scripts/lib/sp1-circuit-tooling";
import { readDesignations } from "../scripts/lib/sp1-designation";
import {
  PROVING_ARTIFACTS_OBSERVATION_REL,
  provingAvailabilityStatus,
  type ProvingArtifactsObservation,
} from "../scripts/lib/sp1-proving-availability";
import { tempDirs } from "./helpers/circuit-tooling";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const reasons = (errs: readonly { reason: string }[]) => [...new Set(errs.map((e) => e.reason))];

// ---------------------------------------------------------------------------------------------------------------
// Synthetic observations: two hosts, two mirrors, one archive, all for the synthetic anchor
// ---------------------------------------------------------------------------------------------------------------

const ARCHIVE = { file: "v6.1.0-groth16.tar.gz", bytes: 6211, sha256: sha256("synthetic archive bytes") };
const UPSTREAM = "https://upstream.invalid/v6.1.0-groth16.tar.gz";
const IMAGE = "registry.invalid/walletwall/synthetic-gnark:v6.1.0";
const AMD64_MANIFEST = `sha256:${sha256("amd64 manifest")}`;
const ATTESTATION_MANIFEST = `sha256:${sha256("attestation manifest")}`;
const INDEX_DIGEST = `sha256:${sha256("the index")}`;
const SCRIPTS = { acquisition: sha256("the acquisition script"), mirror: sha256("the mirror script") };
const CENSUS_SHA = sha256("the census");

const EXPECT: AcquisitionExpectations = {
  anchor: SYNTHETIC_ANCHOR,
  gnarkImage: IMAGE,
  censusSha256: CENSUS_SHA,
  scripts: SCRIPTS,
};

function observation(
  host: string,
  when: { started: string; finished: string; measured: string },
): AcquisitionObservation {
  return {
    schema: ACQUISITION_SCHEMA,
    host,
    measuredAtUtc: when.measured,
    tool: { script: ACQUISITION_SCRIPT_REL, scriptSha256: SCRIPTS.acquisition },
    anchor: clone(SYNTHETIC_ANCHOR),
    archive: { ...ARCHIVE },
    transfer: {
      sourceUrl: UPSTREAM,
      urlEffective: UPSTREAM,
      httpCode: 200,
      remoteIp: "192.0.2.1",
      timeTotalSeconds: 74.4,
      startedAtUtc: when.started,
      finishedAtUtc: when.finished,
      responseHeaders: {
        lastModified: "Wed, 15 Apr 2026 23:37:14 GMT",
        etag: '"etag"',
        contentLength: ARCHIVE.bytes,
        server: "AmazonS3",
      },
    },
    independentDigests: [
      { tool: "coreutils", sha256: ARCHIVE.sha256 },
      { tool: "openssl", sha256: ARCHIVE.sha256 },
    ],
    inspection: {
      members: membersOf(UPSTREAM_SHAPED_FILES),
      directories: [],
      metadata: appleDoubleMetadata(UPSTREAM_SHAPED_FILES),
      provenance: PROVENANCE_ENTRIES.map((e) => ({
        entry: e.path === "" ? "." : e.path,
        key: PROVENANCE_PAX_KEY,
        disposition: "IGNORED_PROVENANCE_METADATA" as const,
      })),
    },
    census: {
      schema: "walletwall.sp1-circuit-archive-census.v1",
      sha256: CENSUS_SHA,
      entries: 24,
      decompressedBytes: 8415018496,
      appleDoubleEntries: 8,
    },
    gnark: {
      repository: "registry.invalid/walletwall/synthetic-gnark",
      tag: "v6.1.0",
      index: {
        digest: INDEX_DIGEST,
        dockerContentDigest: INDEX_DIGEST,
        mediaType: OCI_INDEX,
        bytes: 855,
        manifests: [
          {
            digest: AMD64_MANIFEST,
            mediaType: OCI_MANIFEST,
            size: 866,
            platform: { ...LINUX_AMD64 },
            annotations: null,
          },
          {
            digest: ATTESTATION_MANIFEST,
            mediaType: OCI_MANIFEST,
            size: 565,
            platform: { architecture: "unknown", os: "unknown" },
            annotations: {
              "vnd.docker.reference.digest": AMD64_MANIFEST,
              "vnd.docker.reference.type": "attestation-manifest",
            },
          },
        ],
      },
      platforms: [
        {
          digest: AMD64_MANIFEST,
          mediaType: OCI_MANIFEST,
          platform: { ...LINUX_AMD64 },
          config: { digest: `sha256:${sha256("config")}`, size: 1234 },
          layers: [{ digest: `sha256:${sha256("layer")}`, size: 56789 }],
        },
      ],
      method: REGISTRY_METHOD,
      crossCheck: { tool: "docker buildx imagetools inspect --raw", indexSha256: INDEX_DIGEST.slice(7) },
      observedAtUtc: when.measured,
    },
    platform: [`host=${host}`],
  };
}
const hostA = () =>
  observation("developer-workstation", {
    started: "2026-10-17T22:16:46Z",
    finished: "2026-10-17T22:22:39Z",
    measured: "2026-10-18T23:58:29Z",
  });
const hostB = () =>
  observation("github-hosted-runner", {
    started: "2026-10-19T00:02:00Z",
    finished: "2026-10-19T00:03:20Z",
    measured: "2026-10-19T00:08:00Z",
  });

function mirror(location: string, urlHost: string): MirrorObservation {
  return {
    schema: MIRROR_SCHEMA,
    host: "developer-workstation",
    measuredAtUtc: "2026-10-19T01:00:00Z",
    tool: { script: MIRROR_SCRIPT_REL, scriptSha256: SCRIPTS.mirror },
    location,
    control: "WalletWall (synthetic)",
    fetch: {
      urlHost,
      urlPath: "/sp1/groth16/v6.1.0/v6.1.0-groth16.tar.gz",
      httpCode: 200,
      startedAtUtc: "2026-10-19T00:50:00Z",
      finishedAtUtc: "2026-10-19T00:59:00Z",
      responseHeaders: { lastModified: null, etag: null, contentLength: ARCHIVE.bytes },
    },
    bytes: ARCHIVE.bytes,
    sha256: ARCHIVE.sha256,
    expected: { bytes: ARCHIVE.bytes, sha256: ARCHIVE.sha256 },
    agreement: AGREES,
  };
}
const mirrorA = () =>
  mirror("gs://walletwall-synthetic-a/sp1/groth16/v6.1.0/v6.1.0-groth16.tar.gz#generation=1", "storage.googleapis.com");
const mirrorB = () =>
  mirror("r2://walletwall-synthetic-b/sp1/groth16/v6.1.0/v6.1.0-groth16.tar.gz", "synthetic-b.r2.invalid");

const errorsOf = (f: (a: AcquisitionObservation) => void) => {
  const a = hostA();
  f(a);
  return reasons(acquisitionObservationErrors(a, 0, EXPECT));
};
const agreementOf = (f: (a: AcquisitionObservation, b: AcquisitionObservation, m: MirrorObservation[]) => void) => {
  const a = hostA();
  const b = hostB();
  const m = [mirrorA(), mirrorB()];
  f(a, b, m);
  return reasons(acquisitionErrors([a, b], m, EXPECT));
};

// ---------------------------------------------------------------------------------------------------------------
// A fake registry
// ---------------------------------------------------------------------------------------------------------------

function fakeRegistry(
  over: Partial<{
    dcd: string;
    indexMediaType: string;
    manifestBytes: Buffer;
    manifestSize: number;
    status: number;
  }> = {},
) {
  const manifest =
    over.manifestBytes ??
    Buffer.from(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: OCI_MANIFEST,
        config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: `sha256:${sha256("cfg")}`, size: 10 },
        layers: [
          { mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: `sha256:${sha256("l1")}`, size: 20 },
        ],
      }),
    );
  const manifestDigest = `sha256:${sha256(manifest)}`;
  const attestation = Buffer.from(
    JSON.stringify({ schemaVersion: 2, mediaType: OCI_MANIFEST, config: {}, layers: [] }),
  );
  const indexMediaType = over.indexMediaType ?? OCI_INDEX;
  const index = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: indexMediaType,
      manifests: [
        {
          mediaType: OCI_MANIFEST,
          digest: manifestDigest,
          size: over.manifestSize ?? manifest.length,
          platform: { ...LINUX_AMD64 },
        },
        {
          mediaType: OCI_MANIFEST,
          digest: `sha256:${sha256(attestation)}`,
          size: attestation.length,
          platform: { architecture: "unknown", os: "unknown" },
          annotations: { "vnd.docker.reference.type": "attestation-manifest" },
        },
      ],
    }),
  );
  const indexDigest = `sha256:${sha256(index)}`;
  const calls: string[] = [];
  const fetchImpl: Fetch = async (url, init) => {
    calls.push(`${url} ${init.headers.Accept ?? ""} ${init.headers.Authorization ? "auth" : "anon"}`);
    if (url === "https://registry.invalid/v2/") {
      return new Response("", {
        status: 401,
        headers: {
          "www-authenticate":
            'Bearer realm="https://registry.invalid/token",service="registry.invalid",scope="repository:walletwall/synthetic-gnark:pull"',
        },
      });
    }
    if (url.startsWith("https://registry.invalid/token?"))
      return new Response(JSON.stringify({ token: "anonymous-pull" }), { status: 200 });
    if (url === "https://registry.invalid/v2/walletwall/synthetic-gnark/manifests/v6.1.0") {
      return new Response(index, {
        status: over.status ?? 200,
        headers: { "docker-content-digest": over.dcd ?? indexDigest, "content-type": indexMediaType },
      });
    }
    if (url === `https://registry.invalid/v2/walletwall/synthetic-gnark/manifests/${manifestDigest}`) {
      return new Response(manifest, {
        status: 200,
        headers: { "docker-content-digest": manifestDigest, "content-type": OCI_MANIFEST },
      });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, index, indexDigest, manifest, manifestDigest, calls };
}

describe("SP1-PA2B circuit acquisition: observations, agreement, the derived record and the evidence", function () {
  const dirs = tempDirs();
  afterEach(() => dirs.cleanup());

  describe("registry resolution (a tag to its immutable digest, without a pull)", function () {
    it("resolves the tag to the raw index's digest, confirms Docker-Content-Digest, and fetches each platform manifest by digest", async function () {
      const reg = fakeRegistry();
      const r = await resolveImageTag(IMAGE, reg.fetchImpl);
      expect(r.repository).to.equal("registry.invalid/walletwall/synthetic-gnark");
      expect(r.tag).to.equal("v6.1.0");
      expect(r.index.digest).to.equal(reg.indexDigest);
      expect(r.index.dockerContentDigest).to.equal(reg.indexDigest);
      expect(r.index.mediaType).to.equal(OCI_INDEX);
      expect(r.index.bytes).to.equal(reg.index.length);
      expect(r.index.manifests).to.have.length(2);
      expect(r.platforms).to.have.length(1);
      expect(r.platforms[0]).to.deep.include({ digest: reg.manifestDigest, platform: { ...LINUX_AMD64 } });
      expect(r.platforms[0].config.digest).to.equal(`sha256:${sha256("cfg")}`);
      expect(r.method).to.equal(REGISTRY_METHOD);
      // The attestation manifest (platform unknown) is listed, never fetched; the tag is read once, the manifest once.
      expect(reg.calls.filter((c) => c.includes("/manifests/"))).to.have.length(2);
      expect(reg.calls.every((c) => !c.includes("/blobs/"))).to.equal(true);
    });

    it("refuses a served digest that is not the bytes', a non-index tag, a manifest with other bytes, a size mismatch, and a refusal", async function () {
      const fail = async (reg: ReturnType<typeof fakeRegistry>, re: RegExp) => {
        let message = "";
        try {
          await resolveImageTag(IMAGE, reg.fetchImpl);
        } catch (error) {
          message = (error as Error).message;
        }
        expect(message).to.match(re);
      };
      await fail(fakeRegistry({ dcd: `sha256:${"0".repeat(64)}` }), /Docker-Content-Digest .* is not the bytes'/);
      await fail(fakeRegistry({ indexMediaType: OCI_MANIFEST }), /not a multi-platform index/);
      await fail(fakeRegistry({ manifestSize: 1 }), /the index says 1/);
      await fail(fakeRegistry({ status: 404 }), /answered 404/);
      const other = fakeRegistry();
      const served = other.fetchImpl;
      const swapped: Fetch = (url, init) =>
        url.endsWith(other.manifestDigest)
          ? Promise.resolve(new Response("other bytes", { status: 200 }))
          : served(url, init);
      let message = "";
      try {
        await resolveImageTag(IMAGE, swapped);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).to.match(/served other bytes/);
      // A Docker manifest list is an index too.
      const list = fakeRegistry({ indexMediaType: DOCKER_MANIFEST_LIST });
      expect((await resolveImageTag(IMAGE, list.fetchImpl)).index.mediaType).to.equal(DOCKER_MANIFEST_LIST);
    });

    it("parses only fully qualified registry/repository:tag references", function () {
      expect(parseTaggedRef("ghcr.io/succinctlabs/sp1-gnark:v6.1.0")).to.deep.equal({
        registry: "ghcr.io",
        repository: "succinctlabs/sp1-gnark",
        tag: "v6.1.0",
      });
      for (const bad of [
        "sp1-gnark:v6.1.0",
        "succinctlabs/sp1-gnark:v6.1.0",
        "ghcr.io/succinctlabs/sp1-gnark",
        "ghcr.io/succinctlabs/sp1-gnark@sha256:abc",
        "ghcr.io/Succinct/x:1",
      ]) {
        expect(() => parseTaggedRef(bad), bad).to.throw(/fully qualified/);
      }
    });
  });

  describe("one host's observation", function () {
    it("accepts the synthetic observation (the positive control)", function () {
      expect(acquisitionObservationErrors(hostA(), 0, EXPECT)).to.deep.equal([]);
    });

    it("binds the schema, the host label, the measuring script and the anchor", function () {
      expect(errorsOf((a) => (a.schema = "walletwall.sp1-circuit-acquisition.v0"))).to.include("OBSERVATION_SCHEMA");
      expect(errorsOf((a) => (a.host = "Host A"))).to.include("OBSERVATION_HOST");
      expect(errorsOf((a) => (a.tool.scriptSha256 = sha256("another script")))).to.include("TOOL_NOT_BOUND");
      expect(errorsOf((a) => (a.tool.script = "scripts/other.ts"))).to.include("TOOL_NOT_BOUND");
      expect(errorsOf((a) => (a.anchor.verifier.verifierHash = `0x${"1".repeat(64)}`))).to.include("ANCHOR_MISMATCH");
      expect(errorsOf((a) => (a.anchor.designation = "mldsa65-withdrawal-d1"))).to.include("ANCHOR_MISMATCH");
      expect(reasons(acquisitionObservationErrors(null, 0, EXPECT))).to.deep.equal(["OBSERVATION_SHAPE"]);
    });

    it("holds the archive to its name, and the transfer to a complete https download of exactly those bytes", function () {
      expect(errorsOf((a) => (a.archive.file = "v6.0.0-groth16.tar.gz"))).to.include("ARCHIVE_FIELD");
      expect(errorsOf((a) => (a.archive.bytes = 0))).to.include("ARCHIVE_FIELD");
      expect(errorsOf((a) => (a.transfer.httpCode = 206))).to.include("TRANSFER_INCOMPLETE");
      expect(errorsOf((a) => (a.transfer.responseHeaders.contentLength = ARCHIVE.bytes + 1))).to.include(
        "TRANSFER_INCOMPLETE",
      );
      expect(errorsOf((a) => (a.transfer.urlEffective = "http://upstream.invalid/v6.1.0-groth16.tar.gz"))).to.include(
        "TRANSFER_FIELD",
      );
      expect(errorsOf((a) => (a.transfer.urlEffective = "https://upstream.invalid/other.tar.gz"))).to.include(
        "TRANSFER_FIELD",
      );
      expect(errorsOf((a) => (a.transfer.finishedAtUtc = "2026-10-17T22:00:00Z"))).to.include("TRANSFER_FIELD");
      expect(errorsOf((a) => (a.measuredAtUtc = "2026-10-17T22:20:00Z"))).to.include("OBSERVATION_FIELD");
      expect(errorsOf((a) => delete (a.transfer.responseHeaders as any).etag)).to.include("TRANSFER_FIELD");
      // A null Content-Length (a server that sent none) is allowed: the measured length is the fact.
      expect(errorsOf((a) => (a.transfer.responseHeaders.contentLength = null))).to.deep.equal([]);
    });

    it("needs two independent digest implementations that agree with the inspector's", function () {
      expect(errorsOf((a) => a.independentDigests.pop())).to.include("DIGESTS_NOT_INDEPENDENT");
      expect(errorsOf((a) => (a.independentDigests[1].tool = "coreutils"))).to.include("DIGESTS_NOT_INDEPENDENT");
      expect(errorsOf((a) => (a.independentDigests[1].sha256 = sha256("other")))).to.include("DIGEST_DISAGREES");
    });

    it("needs the merged inspector's measurement: a refused copy, directories, or another key", function () {
      expect(errorsOf((a) => ((a as any).inspection = null))).to.include("INSPECTION_MISSING");
      expect(errorsOf((a) => (a.inspection.members = []))).to.include("INSPECTION_MISSING");
      expect(errorsOf((a) => (a.inspection.directories = ["extra"]))).to.include("INSPECTION_FIELD");
      expect(
        errorsOf((a) => (a.inspection.members = a.inspection.members.filter((m) => m.path !== VK_FILE))),
      ).to.include("VK_MISMATCH");
      expect(
        errorsOf(
          (a) =>
            (a.inspection.members = a.inspection.members.map((m) =>
              m.path === VK_FILE ? { ...m, sha256: sha256("other key") } : m,
            )),
        ),
      ).to.include("VK_MISMATCH");
    });

    it("needs the census of this copy to be the committed census", function () {
      expect(errorsOf((a) => (a.census.sha256 = sha256("another census")))).to.include("CENSUS_MISMATCH");
      expect(errorsOf((a) => ((a as any).census = null))).to.include("CENSUS_MISSING");
    });

    it("needs the pinned prover's image resolved to one immutable index with one linux/amd64 manifest, fetched by digest", function () {
      expect(errorsOf((a) => (a.gnark.tag = "latest"))).to.include("GNARK_IMAGE_MISMATCH");
      expect(errorsOf((a) => (a.gnark.repository = "registry.invalid/other/synthetic-gnark"))).to.include(
        "GNARK_IMAGE_MISMATCH",
      );
      expect(errorsOf((a) => (a.gnark.index.digest = "v6.1.0"))).to.include("GNARK_NOT_DIGEST_PINNED");
      expect(errorsOf((a) => (a.gnark.index.dockerContentDigest = `sha256:${"0".repeat(64)}`))).to.include(
        "GNARK_DIGEST_UNCONFIRMED",
      );
      expect(errorsOf((a) => (a.gnark.index.mediaType = OCI_MANIFEST))).to.include("GNARK_NOT_AN_INDEX");
      expect(errorsOf((a) => a.gnark.index.manifests.push({ ...a.gnark.index.manifests[0] }))).to.include(
        "GNARK_PLATFORM_AMBIGUOUS",
      );
      expect(
        errorsOf((a) => (a.gnark.index.manifests[0].platform = { architecture: "arm64", os: "linux" })),
      ).to.include("GNARK_PLATFORM_AMBIGUOUS");
      expect(errorsOf((a) => (a.gnark.platforms = []))).to.include("GNARK_PLATFORM_UNRESOLVED");
      expect(errorsOf((a) => (a.gnark.platforms[0].digest = `sha256:${"1".repeat(64)}`))).to.include(
        "GNARK_PLATFORM_UNRESOLVED",
      );
      expect(errorsOf((a) => (a.gnark.method = "docker pull"))).to.include("GNARK_METHOD");
      expect(errorsOf((a) => ((a.gnark.crossCheck as any).indexSha256 = "0".repeat(64)))).to.include(
        "GNARK_CROSS_CHECK_DISAGREES",
      );
      expect(errorsOf((a) => (a.gnark.crossCheck = null))).to.deep.equal([]);
      expect(errorsOf((a) => ((a as any).gnark = null))).to.include("GNARK_MISSING");
      expect(errorsOf((a) => (a.platform = []))).to.include("OBSERVATION_FIELD");
    });
  });

  describe("the hosts against each other", function () {
    it("accepts two agreeing hosts and two mirrors (the positive control)", function () {
      expect(acquisitionErrors([hostA(), hostB()], [mirrorA(), mirrorB()], EXPECT)).to.deep.equal([]);
    });

    it("needs at least two observations from distinct host labels", function () {
      expect(reasons(acquisitionErrors([hostA()], [mirrorA(), mirrorB()], EXPECT))).to.include("ACQUISITIONS_MISSING");
      expect(agreementOf((_a, b) => (b.host = "developer-workstation"))).to.include("ACQUISITION_NOT_INDEPENDENT");
      // One host relabeled as another: the same transfer window and platform lines are two observations only in name.
      expect(
        reasons(
          acquisitionErrors([hostA(), { ...hostA(), host: "github-hosted-runner" }], [mirrorA(), mirrorB()], EXPECT),
        ),
      ).to.deep.equal([]);
      // That is why the record binds the hosts' own identity lines and transfer windows: the review checks them, the
      // validator cannot tell two machines apart. The observations' agreement is what it can check.
    });

    it("stops on any disagreement: bytes, sha256, file, URL, inspection, census, image or platform manifests", function () {
      // Each host B is tampered self-consistently (its own Content-Length, digests and file agree with its copy), so
      // only the cross-host layer can refuse it: a host whose own measurement is inconsistent is refused earlier.
      expect(agreementOf((_a, b) => (b.transfer.responseHeaders.contentLength = ++b.archive.bytes))).to.include(
        "HOSTS_DISAGREE",
      );
      expect(
        agreementOf((_a, b) => {
          b.archive.file = "v6.1.0-groth16.tar.gz";
          b.transfer.urlEffective = b.transfer.sourceUrl = "https://upstream.invalid/mirror/v6.1.0-groth16.tar.gz";
        }),
      ).to.include("HOSTS_DISAGREE");
      expect(
        agreementOf(
          (_a, b) => (b.archive.sha256 = b.independentDigests[0].sha256 = b.independentDigests[1].sha256 = sha256("x")),
        ),
      ).to.include("HOSTS_DISAGREE");
      expect(
        agreementOf(
          (_a, b) => (b.transfer.urlEffective = b.transfer.sourceUrl = "https://mirror.invalid/v6.1.0-groth16.tar.gz"),
        ),
      ).to.include("HOSTS_DISAGREE");
      expect(agreementOf((_a, b) => (b.inspection.metadata = b.inspection.metadata.slice(1)))).to.include(
        "HOSTS_DISAGREE",
      );
      expect(agreementOf((_a, b) => (b.inspection.provenance = b.inspection.provenance.slice(1)))).to.include(
        "HOSTS_DISAGREE",
      );
      expect(agreementOf((_a, b) => (b.inspection.members[0].sha256 = sha256("tampered member")))).to.include(
        "HOSTS_DISAGREE",
      );
      expect(
        agreementOf((_a, b) => (b.gnark.platforms[0].config.digest = `sha256:${sha256("other config")}`)),
      ).to.include("HOSTS_DISAGREE");
      const otherIndex = `sha256:${sha256("another index")}`;
      expect(
        agreementOf((_a, b) => {
          b.gnark.index.digest = b.gnark.index.dockerContentDigest = otherIndex;
          (b.gnark.crossCheck as any).indexSha256 = otherIndex.slice(7);
        }),
      ).to.include("HOSTS_DISAGREE");
    });
  });

  describe("the mirrors", function () {
    const archive = { bytes: ARCHIVE.bytes, sha256: ARCHIVE.sha256, upstreamHost: "upstream.invalid" };
    const mirrorErrors = (f: (m: MirrorObservation) => void) => {
      const m = mirrorA();
      f(m);
      return reasons(mirrorObservationErrors(m, 0, archive, SCRIPTS.mirror));
    };

    it("accepts a mirror re-read byte for byte (the positive control)", function () {
      expect(mirrorObservationErrors(mirrorA(), 0, archive, SCRIPTS.mirror)).to.deep.equal([]);
    });

    it("needs two mirrors at distinct locations, neither the upstream source", function () {
      expect(reasons(acquisitionErrors([hostA(), hostB()], [mirrorA()], EXPECT))).to.include("MIRRORS_MISSING");
      expect(agreementOf((_a, _b, m) => (m[1].location = m[0].location))).to.include("MIRRORS_NOT_DISTINCT");
      // One location spelled twice: scheme and host case-folded, a trailing slash; the object path keeps its case.
      expect(
        agreementOf(
          (_a, _b, m) =>
            (m[1].location = `${m[0].location.replace("gs://walletwall-synthetic-a", "GS://WALLETWALL-SYNTHETIC-A")}/`),
        ),
      ).to.include("MIRRORS_NOT_DISTINCT");
      expect(agreementOf((_a, _b, m) => (m[1].location = m[0].location.replace("/sp1/", "/SP1/")))).to.deep.equal([]);
      expect(agreementOf((_a, _b, m) => (m[1].fetch.urlHost = "upstream.invalid"))).to.include("MIRROR_IS_UPSTREAM");
      expect(agreementOf((_a, _b, m) => (m[1].location = UPSTREAM))).to.include("MIRROR_IS_UPSTREAM");
      expect(normalizedLocation("GS://Bucket/Obj/")).to.equal("gs://bucket/Obj");
      expect(normalizedLocation(" gs://bucket/obj ")).to.equal("gs://bucket/obj");
    });

    it("needs the archive's bytes, agreed, by the committed script, in one complete read with no signed query recorded", function () {
      expect(mirrorErrors((m) => (m.bytes += 1))).to.include("MIRROR_DISAGREES");
      expect(mirrorErrors((m) => (m.sha256 = sha256("other")))).to.include("MIRROR_DISAGREES");
      expect(mirrorErrors((m) => (m.agreement = "DISAGREES"))).to.include("MIRROR_DISAGREES");
      expect(mirrorErrors((m) => (m.expected.sha256 = sha256("other")))).to.include("MIRROR_DISAGREES");
      expect(mirrorErrors((m) => (m.tool.scriptSha256 = sha256("other script")))).to.include("TOOL_NOT_BOUND");
      expect(mirrorErrors((m) => (m.fetch.httpCode = 206))).to.include("MIRROR_INCOMPLETE");
      expect(mirrorErrors((m) => (m.fetch.responseHeaders.contentLength = 1))).to.include("MIRROR_INCOMPLETE");
      expect(mirrorErrors((m) => (m.fetch.urlPath = "/obj?X-Goog-Signature=abc"))).to.include("MIRROR_FIELD");
      expect(mirrorErrors((m) => (m.schema = "walletwall.sp1-circuit-mirror.v0"))).to.include("MIRROR_SCHEMA");
      expect(mirrorErrors((m) => (m.control = ""))).to.include("MIRROR_FIELD");
      expect(mirrorErrors((m) => (m.measuredAtUtc = "2026-10-19T00:55:00Z"))).to.include("MIRROR_FIELD");
      expect(reasons(mirrorObservationErrors("not an object", 0, archive, SCRIPTS.mirror))).to.deep.equal([
        "MIRROR_SHAPE",
      ]);
    });
  });

  describe("the derived record", function () {
    it("is accepted by the PA2A record validator for the anchor, and binds every measured fact", function () {
      const r = deriveArchiveRecord([hostB(), hostA()], [mirrorB(), mirrorA()], EXPECT);
      expect(archiveRecordErrors(r, SYNTHETIC_ANCHOR)).to.deep.equal([]);
      expect(r.subject.verifyingKey).to.deep.equal({ file: VK_FILE, ...SYNTHETIC_ANCHOR.verifyingKey });
      expect(r.archive).to.deep.include({
        ...ARCHIVE,
        acquiredAtUtc: "2026-10-17T22:22:39Z",
        sourceUrl: UPSTREAM,
        sourceUrlRole: "PROVENANCE_ONLY",
      });
      expect(r.acquisitions.map((a) => a.host)).to.deep.equal(["developer-workstation", "github-hosted-runner"]);
      expect(
        r.acquisitions.every((a) => a.agreement === AGREES && a.sha256 === ARCHIVE.sha256 && a.bytes === ARCHIVE.bytes),
      ).to.equal(true);
      expect(r.members.map((m) => m.path)).to.deep.equal([...r.members.map((m) => m.path)].sort());
      expect(r.members).to.deep.equal(membersOf(UPSTREAM_SHAPED_FILES));
      expect(r.metadata).to.deep.equal(appleDoubleMetadata(UPSTREAM_SHAPED_FILES));
      expect(r.gnark).to.deep.include({
        repository: "registry.invalid/walletwall/synthetic-gnark",
        tag: "v6.1.0",
        tagRole: "PROVENANCE_ONLY",
        digest: INDEX_DIGEST,
        mirror: null,
      });
      expect(r.gnark.observation.host).to.equal("developer-workstation");
      expect(r.gnark.observation.method).to.include(AMD64_MANIFEST);
      expect(r.gnark.observation.method).to.include("developer-workstation and github-hosted-runner");
      expect(r.mirrors).to.deep.equal([
        { location: mirrorA().location, sha256: ARCHIVE.sha256 },
        { location: mirrorB().location, sha256: ARCHIVE.sha256 },
      ]);
      expect(serializeJson(r)).to.equal(
        serializeJson(deriveArchiveRecord([hostA(), hostB()], [mirrorA(), mirrorB()], EXPECT)),
      );
    });

    it("is not derived at all from observations that do not agree, naming every reason", function () {
      const b = hostB();
      b.transfer.responseHeaders.contentLength = ++b.archive.bytes;
      expect(() => deriveArchiveRecord([hostA(), b], [mirrorA()], EXPECT)).to.throw(
        /HOSTS_DISAGREE[\s\S]*MIRRORS_MISSING/,
      );
      // An observation inconsistent with itself is refused before the hosts are compared at all.
      const c = hostB();
      c.archive.bytes += 1;
      expect(() => deriveArchiveRecord([hostA(), c], [mirrorA(), mirrorB()], EXPECT)).to.throw(/TRANSFER_INCOMPLETE/);
    });
  });

  describe("the committed evidence (a temporary repository)", function () {
    const git = (cwd: string, ...args: string[]) => {
      const r = spawnSync("git", args, { cwd, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout;
    };
    const input = { anchor: SYNTHETIC_ANCHOR, gnarkImage: IMAGE };
    /** A repository holding the synthetic census, the real measuring scripts and, optionally, the observations and record. */
    function repo(opts: { observations?: boolean; record?: boolean; commit?: boolean } = {}): string {
      const d = dirs.make("sp1-pa2b-");
      git(d, "init", "-q");
      git(d, "config", "user.email", "test@example.invalid");
      git(d, "config", "user.name", "test");
      git(d, "config", "commit.gpgsign", "false");
      mkdirSync(join(d, OBSERVATIONS_DIR), { recursive: true });
      mkdirSync(join(d, "scripts/lib"), { recursive: true });
      for (const rel of CENSUS_OBSERVATIONS_REL) {
        writeFileSync(
          join(d, rel),
          serializeJson({ schema: "walletwall.sp1-circuit-archive-census.v1", synthetic: true }),
        );
      }
      cpSync(resolve(ACQUISITION_SCRIPT_REL), join(d, ACQUISITION_SCRIPT_REL));
      cpSync(resolve(MIRROR_SCRIPT_REL), join(d, MIRROR_SCRIPT_REL));
      const expect = acquisitionExpectations(d, input);
      const bind = <T extends { tool: { scriptSha256: string }; census?: { sha256: string } }>(
        o: T,
        script: string,
      ): T => {
        o.tool.scriptSha256 = script;
        if (o.census) o.census.sha256 = expect.censusSha256;
        return o;
      };
      const a = bind(hostA(), expect.scripts.acquisition);
      const b = bind(hostB(), expect.scripts.acquisition);
      const m1 = bind(mirrorA(), expect.scripts.mirror);
      const m2 = bind(mirrorB(), expect.scripts.mirror);
      if (opts.observations !== false) {
        writeFileSync(join(d, ACQUISITION_OBSERVATIONS_REL[0]), serializeJson(a));
        writeFileSync(join(d, ACQUISITION_OBSERVATIONS_REL[1]), serializeJson(b));
        writeFileSync(join(d, OBSERVATIONS_DIR, "circuit-archive-mirror-a.raw.json"), serializeJson(m1));
        writeFileSync(join(d, OBSERVATIONS_DIR, "circuit-archive-mirror-b.raw.json"), serializeJson(m2));
      }
      if (opts.record !== false) {
        mkdirSync(join(d, PROVING_ARCHIVES_DIR), { recursive: true });
        writeFileSync(
          join(d, productionRecordRel(SYNTHETIC_ANCHOR)),
          serializeJson(deriveArchiveRecord([a, b], [m1, m2], expect)),
        );
      }
      if (opts.commit !== false) {
        git(d, "add", "-A");
        git(d, "commit", "-q", "-m", "evidence");
      }
      return d;
    }
    const judge = (d: string) => productionArchiveEvidence(d, input);

    it("is NO_RECORD while the archive directory holds nothing, whatever observations exist", function () {
      this.timeout(60_000);
      const d = repo({ record: false });
      const e = judge(d);
      expect(archiveEvidenceState(e)).to.equal("NO_RECORD");
      expect(e).to.deep.include({ records: [], record: null, errors: [] });
      expect(archiveEvidenceState(judge(repo({ record: false, observations: false })))).to.equal("NO_RECORD");
    });

    it("is ACCEPTED only for the one record the committed observations derive, committed with them", function () {
      this.timeout(60_000);
      const d = repo();
      const e = judge(d);
      expect(e.errors).to.deep.equal([]);
      expect(archiveEvidenceState(e)).to.equal("ACCEPTED");
      expect(e.records).to.deep.equal([productionRecordRel(SYNTHETIC_ANCHOR)]);
      expect(e.observations).to.deep.equal([...ACQUISITION_OBSERVATIONS_REL, ...mirrorObservationsIn(d)]);
      expect(mirrorObservationsIn(d)).to.have.length(2);
      expect((e.record as ArchiveRecord).archive.sha256).to.equal(ARCHIVE.sha256);
      expect(archiveRecordsIn(d)).to.deep.equal(e.records);
    });

    it("is REFUSED, never NO_RECORD, for an uncommitted record, a hand-edited one, a second file, a missing or edited observation, or a mirror removed", function () {
      this.timeout(120_000);
      const recordPath = (d: string) => join(d, productionRecordRel(SYNTHETIC_ANCHOR));
      const refused = (d: string, re: RegExp) => {
        const e = judge(d);
        expect(archiveEvidenceState(e), e.errors.join("; ")).to.equal("REFUSED");
        expect(e.record).to.equal(null);
        expect(e.errors.join("\n")).to.match(re);
      };
      refused(repo({ commit: false }), /not as committed: NOT_A_GIT_CHECKOUT|UNTRACKED|UNCOMMITTED/);
      let d = repo();
      const edited = JSON.parse(readFileSync(recordPath(d), "utf8")) as ArchiveRecord;
      edited.mirrors[0].location = "gs://walletwall-synthetic-c/v6.1.0-groth16.tar.gz";
      writeFileSync(recordPath(d), serializeJson(edited));
      refused(d, /is not the record the committed observations derive/);
      d = repo();
      writeFileSync(join(d, PROVING_ARCHIVES_DIR, "another.json"), "{}\n");
      refused(d, /must hold exactly/);
      d = repo();
      rmSync(join(d, ACQUISITION_OBSERVATIONS_REL[1]));
      refused(d, /observations are missing/);
      d = repo();
      const b = JSON.parse(readFileSync(join(d, ACQUISITION_OBSERVATIONS_REL[1]), "utf8")) as AcquisitionObservation;
      b.archive.sha256 = sha256("other bytes");
      writeFileSync(join(d, ACQUISITION_OBSERVATIONS_REL[1]), serializeJson(b));
      refused(d, /DIGEST_DISAGREES|HOSTS_DISAGREE/);
      d = repo();
      rmSync(join(d, OBSERVATIONS_DIR, "circuit-archive-mirror-b.raw.json"));
      git(d, "add", "-A");
      git(d, "commit", "-q", "-m", "a mirror removed");
      refused(d, /MIRRORS_MISSING/);
      d = repo();
      const renamed = join(d, PROVING_ARCHIVES_DIR, "v6.1.0.json");
      writeFileSync(renamed, readFileSync(recordPath(d)));
      rmSync(recordPath(d));
      git(d, "add", "-A");
      git(d, "commit", "-q", "-m", "renamed");
      refused(d, /must hold exactly/);
      d = repo();
      const a = JSON.parse(readFileSync(join(d, ACQUISITION_OBSERVATIONS_REL[0]), "utf8")) as AcquisitionObservation;
      a.platform.push("edited after the commit");
      writeFileSync(join(d, ACQUISITION_OBSERVATIONS_REL[0]), serializeJson(a));
      refused(d, /not as committed: UNCOMMITTED/);
    });
  });

  describe("the state, derived from the evidence", function () {
    const noRecord: ArchiveEvidence = { records: [], record: null, observations: [], errors: [] };
    const accepted: ArchiveEvidence = {
      records: [productionRecordRel(SYNTHETIC_ANCHOR)],
      record: deriveArchiveRecord([hostA(), hostB()], [mirrorA(), mirrorB()], EXPECT),
      observations: [...ACQUISITION_OBSERVATIONS_REL],
      errors: [],
    };
    const refused: ArchiveEvidence = { ...accepted, record: null, errors: ["MIRRORS_MISSING: one mirror"] };

    it("toolingState: the self-test, then the archive evidence; a refused record derives no state", function () {
      expect(toolingState({ selfTestPassed: false, archive: noRecord })).to.equal("TOOLING_NOT_PRESENT");
      expect(toolingState({ selfTestPassed: true, archive: noRecord })).to.equal("TOOLING_READY_NO_ARTIFACT");
      expect(toolingState({ selfTestPassed: true, archive: accepted })).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      expect(() => toolingState({ selfTestPassed: true, archive: refused })).to.throw(/no state is derivable/);
      expect(() => toolingState({ selfTestPassed: true, archive: { ...noRecord, errors: ["x"] } })).to.throw(
        /no state is derivable/,
      );
      expect(availabilityStatusesFor("ARCHIVED_VERIFIED_UNEXERCISED")).to.deep.equal(["ARCHIVED_VERIFIED_UNEXERCISED"]);
      expect(availabilityStatusesFor("TOOLING_READY_NO_ARTIFACT")).to.deep.equal([
        "OWNER_DOWNLOAD_REQUIRED",
        "LOCAL_COPY_NOT_ARCHIVED",
      ]);
    });

    it("provingAvailabilityStatus: ARCHIVED_VERIFIED_UNEXERCISED only from accepted evidence that judged exactly the records on disk", function () {
      const obs = JSON.parse(readFileSync(PROVING_ARTIFACTS_OBSERVATION_REL, "utf8")) as ProvingArtifactsObservation;
      expect(provingAvailabilityStatus(obs, accepted.records, accepted)).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
      expect(() => provingAvailabilityStatus(obs, accepted.records, null)).to.throw(
        /not an accepted production archive record/,
      );
      expect(() => provingAvailabilityStatus(obs, accepted.records, refused)).to.throw(/MIRRORS_MISSING/);
      expect(() => provingAvailabilityStatus(obs, [], accepted)).to.throw(/judged .* not no record/);
      expect(() => provingAvailabilityStatus(obs, [], { ...noRecord, errors: ["stray"] })).to.throw(
        /refused without a record/,
      );
      expect(provingAvailabilityStatus(obs, [], noRecord)).to.equal("OWNER_DOWNLOAD_REQUIRED");
      const present = { ...obs, local: { ...obs.local, groth16DirPresent: true } };
      expect(provingAvailabilityStatus(present, [], noRecord)).to.equal("LOCAL_COPY_NOT_ARCHIVED");
      // An accepted archive outranks a local copy: the copy is not what proving reads.
      expect(provingAvailabilityStatus(present, accepted.records, accepted)).to.equal("ARCHIVED_VERIFIED_UNEXERCISED");
    });

    it("the production anchor is the designation's, through the one anchor builder", function () {
      const d1 = readDesignations(".").at(-1)!;
      expect(anchorFromDesignation(d1, 492)).to.deep.equal(productionAnchor("."));
      expect(pinnedGnarkImage(".")).to.equal("ghcr.io/succinctlabs/sp1-gnark:v6.1.0");
    });
  });

  describe("the committed observations, when present, are this lane's measurements", function () {
    it("each acquisition observation is bound to the committed script and agrees with the committed census and designation d1", function () {
      const expect_ = acquisitionExpectations(".", {
        anchor: productionAnchor("."),
        gnarkImage: pinnedGnarkImage("."),
      });
      const present = ACQUISITION_OBSERVATIONS_REL.filter((rel) => {
        try {
          readFileSync(rel);
          return true;
        } catch {
          return false;
        }
      });
      if (present.length === 0) this.skip();
      present.forEach((rel, i) => {
        const o = JSON.parse(readFileSync(rel, "utf8")) as AcquisitionObservation;
        expect(acquisitionObservationErrors(o, i, expect_), rel).to.deep.equal([]);
        expect(o.archive).to.deep.equal({
          file: "v6.1.0-groth16.tar.gz",
          bytes: 6211807514,
          sha256: "18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810",
        });
        expect(o.inspection.members.find((m) => m.path === VK_FILE)).to.deep.equal({
          path: VK_FILE,
          bytes: 492,
          sha256: "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696",
        });
        expect(o.inspection.members).to.have.length(7);
        expect(o.inspection.metadata).to.have.length(8);
        expect(o.inspection.provenance).to.have.length(8);
        expect(o.gnark.index.digest).to.equal(
          "sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d",
        );
        expect(o.gnark.platforms.map((p) => p.digest)).to.deep.equal([
          "sha256:be8555f1ad90870acd8c6ec7fd3ba0b1a2133ea9cddf25e130665aa651129e54",
        ]);
      });
    });
  });
});
