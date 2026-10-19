/**
 * SP1-PA2B: the owner-authorized acquisition of SP1's Groth16 circuit archive, measured on two hosts, and the
 * production archive record derived from those measurements
 * (docs/SP1_Circuit_Install_And_Archive_Only_Prove_Gate.md, "SP1-PA2B").
 *
 * Nothing here downloads the archive: a host acquires it by other means (curl on the developer workstation, curl on a
 * GitHub-hosted runner), and scripts/measure-sp1-circuit-acquisition.ts then MEASURES the local copy with the merged
 * PA2A inspector (scripts/lib/sp1-circuit-archive.ts, measuring mode) and the census, records the transfer's
 * provenance and the host's independent digests, and resolves the gnark image tag to its immutable digest from the
 * registry (never a pull). Each host writes one observation. A mirror observation
 * (scripts/measure-sp1-circuit-mirror.ts) records a WalletWall-controlled location re-read byte for byte.
 *
 * The record (walletwall.sp1-proving-archive.v2) is DERIVED from the observations, never written by hand:
 * `deriveArchiveRecord` is a pure function of the anchor and the observations, `acquisitionErrors` names every reason
 * the observations do not derive one (hosts that disagree, a copy the inspector refused, an inspection that differs
 * between hosts, a census other than the committed one, a tag without a digest, hosts that resolve the tag to
 * different images, a mirror that holds other bytes or sits upstream, two mirrors at one location), and
 * `productionArchiveEvidence` holds the committed record to the committed observations, byte for byte. The archive's
 * sha256 is the authority; the upstream URL and the image tag are provenance only.
 *
 * What a record establishes, and what it does not: WalletWall has independently identified, authenticated, recorded
 * and mirrored the exact proving artifacts its designated verifier expects. The verifying-key equality is integrity
 * and compatibility, not evidence that the Groth16 trusted setup is sound; the immutable image digest is supply-chain
 * identity, not proof-system correctness; two mirrors improve availability today and prove nothing about tomorrow;
 * and no proof has been made from the archive. Research prototype. Not audited. Testnet/local only.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  AGREES,
  ARCHIVE_FORMAT,
  ARCHIVE_RECORD_SCHEMA,
  CIRCUIT_SYSTEM,
  MIN_ACQUISITIONS,
  MIN_MIRRORS,
  PROVENANCE_ONLY,
  PROVING_ARCHIVES_DIR,
  VK_FILE,
  archiveRecordErrors,
  archiveRecordsIn,
  imageRefError,
  type ArchiveAnchor,
  type ArchiveMember,
  type ArchiveMetadata,
  type ArchiveRecord,
  type Inspection,
} from "./sp1-circuit-archive";
import { CENSUS_SCHEMA, type Census } from "./sp1-circuit-archive-census";
import { type ProgramDesignation } from "./sp1-designation";
import { uncommittedEvidenceError } from "./committed-evidence";

/**
 * What an archive must serve for designation `d`: its circuit, PROGRAM_VKEY, verifier and VERIFIER_HASH, and the
 * verifying key's length as the proving-artifacts observation measured sp1-verifier's embedded key. Taken from the
 * designation, never from an archive, a record or an observation of one.
 */
export function anchorFromDesignation(d: ProgramDesignation, verifyingKeyBytes: number): ArchiveAnchor {
  return {
    designation: d.id,
    circuitVersion: d.verifier.version,
    programVKey: d.programVKey,
    verifier: {
      version: d.verifier.version,
      runtimeCodeKeccak: d.verifier.runtimeCodeKeccak,
      verifierHash: d.verifier.verifierHash,
    },
    verifyingKey: { sha256: d.verifier.verifierHash, bytes: verifyingKeyBytes },
  };
}

export const ACQUISITION_SCHEMA = "walletwall.sp1-circuit-acquisition.v1";
export const MIRROR_SCHEMA = "walletwall.sp1-circuit-mirror.v1";
export const ACQUISITION_SCRIPT_REL = "scripts/measure-sp1-circuit-acquisition.ts";
export const MIRROR_SCRIPT_REL = "scripts/measure-sp1-circuit-mirror.ts";
export const OBSERVATIONS_DIR = "evidence/zk/sp1-impl/observations";
/** The two acquisition observations a record is derived from: one per host, by the host label the record names. */
export const ACQUISITION_HOSTS: readonly string[] = ["developer-workstation", "github-hosted-runner"];
export const acquisitionObservationRel = (host: string) => `${OBSERVATIONS_DIR}/circuit-acquisition-${host}.raw.json`;
export const ACQUISITION_OBSERVATIONS_REL: readonly string[] = ACQUISITION_HOSTS.map(acquisitionObservationRel);
/** Mirror observations: one file per WalletWall-controlled location, circuit-archive-mirror-<id>.raw.json. */
export const MIRROR_OBSERVATION_PREFIX = "circuit-archive-mirror-";
/**
 * A platform line each host's observation must carry: the runner its run id (an ephemeral machine names its run),
 * the workstation its operating system. A copy of one host's observation relabeled as the other carries the wrong
 * lines; agreement on measured facts never substitutes for a host's own identity.
 */
export const HOST_IDENTITY_MARKERS: Readonly<Record<string, RegExp>> = {
  "developer-workstation": /^os=/,
  "github-hosted-runner": /^run_id=[0-9]+$/,
};
/**
 * The storage providers a WalletWall mirror may live at (the owner's choice: Google Cloud Storage and Cloudflare R2),
 * each with its location grammar and the hosts a re-read of it may be served from. A location names an object as
 * `<scheme>://<bucket>/<object>` (R2: `<account>/<bucket>/<object>`); a re-read's host and path must name the same
 * object under either of the provider's addressing styles (path-style on the provider host, or virtual-hosted on a
 * bucket subdomain). Everything else, the upstream S3 bucket under any alias included, is no WalletWall mirror.
 */
export const MIRROR_PROVIDERS: readonly {
  readonly id: string;
  readonly scheme: string;
  readonly segments: number;
  readonly host: RegExp;
}[] = [
  {
    id: "gcs",
    scheme: "gs",
    segments: 1,
    host: /^(?:([a-z0-9][a-z0-9._-]{1,221}[a-z0-9])\.)?storage\.googleapis\.com$/,
  },
  {
    id: "r2",
    scheme: "r2",
    segments: 2,
    host: /^(?:([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.)?([a-f0-9]{32})\.r2\.cloudflarestorage\.com$/,
  },
];
/** The fields an observation names, level by level: an unknown field (a refusal marker, say) is refused, not ignored. */
export const OBSERVATION_FIELDS = {
  acquisition: [
    "schema",
    "host",
    "measuredAtUtc",
    "tool",
    "anchor",
    "archive",
    "transfer",
    "independentDigests",
    "inspection",
    "census",
    "gnark",
    "platform",
  ],
  tool: ["script", "scriptSha256"],
  archive: ["file", "bytes", "sha256"],
  transfer: [
    "sourceUrl",
    "urlEffective",
    "httpCode",
    "remoteIp",
    "timeTotalSeconds",
    "startedAtUtc",
    "finishedAtUtc",
    "responseHeaders",
  ],
  inspection: ["members", "directories", "metadata", "provenance"],
  census: ["schema", "sha256", "entries", "decompressedBytes", "appleDoubleEntries"],
  gnark: ["repository", "tag", "index", "platforms", "method", "crossCheck", "observedAtUtc"],
  mirror: [
    "schema",
    "host",
    "measuredAtUtc",
    "tool",
    "location",
    "control",
    "fetch",
    "bytes",
    "sha256",
    "expected",
    "agreement",
  ],
  fetch: ["urlHost", "urlPath", "httpCode", "startedAtUtc", "finishedAtUtc", "responseHeaders"],
  expected: ["bytes", "sha256"],
} as const;
/**
 * The census of the upstream v6.1.0 archive (scripts/sp1-circuit-archive-census.ts output, verbatim) on each host that
 * acquired it in SP1-PA2A's amendment: the AppleDouble and provenance policies are derived from them, and every
 * acquisition's census must be exactly this one.
 */
export const CENSUS_OBSERVATIONS_REL: readonly string[] = [
  `${OBSERVATIONS_DIR}/circuit-archive-census-developer-workstation.raw.json`,
  `${OBSERVATIONS_DIR}/circuit-archive-census-github-hosted-runner.raw.json`,
];
export const LINUX_AMD64 = { architecture: "amd64", os: "linux" } as const;
export const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
export const DOCKER_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json";
export const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
export const DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";
export const REGISTRY_METHOD =
  "OCI distribution API: GET /v2/<repository>/manifests/<tag> with an anonymous pull token, the index digest being the sha256 of the raw index bytes and equal to the Docker-Content-Digest header; each platform manifest then fetched by digest and re-hashed; no image pulled";

const HEX64 = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const isObject = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const isCount = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0;
const isText = (x: unknown): x is string => typeof x === "string" && x.length > 0;
function urlHost(x: unknown): string | null {
  try {
    const u = new URL(String(x));
    return u.protocol === "https:" ? u.host : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The observations
// ---------------------------------------------------------------------------------------------------------------

export interface TransferProvenance {
  /** The URL requested and the one the transfer ended at (both https); provenance, never authority. */
  sourceUrl: string;
  urlEffective: string;
  httpCode: number;
  remoteIp: string;
  timeTotalSeconds: number;
  startedAtUtc: string;
  finishedAtUtc: string;
  responseHeaders: {
    lastModified: string | null;
    etag: string | null;
    contentLength: number | null;
    server: string | null;
  };
}

export interface GnarkManifestRef {
  digest: string;
  mediaType: string;
  size: number;
  platform: { architecture: string; os: string; variant?: string } | null;
  /** An attestation manifest names the image manifest it attests; kept so the index is recorded as served. */
  annotations: Record<string, string> | null;
}

export interface GnarkPlatformManifest {
  digest: string;
  mediaType: string;
  platform: { architecture: string; os: string; variant?: string };
  config: { digest: string; size: number };
  layers: { digest: string; size: number }[];
}

export interface GnarkObservation {
  repository: string;
  tag: string;
  index: {
    /** sha256 of the raw index bytes the registry served for the tag: the immutable, multi-platform reference. */
    digest: string;
    dockerContentDigest: string;
    mediaType: string;
    bytes: number;
    manifests: GnarkManifestRef[];
  };
  /** Every image manifest the index lists for a known platform, fetched by its digest and re-hashed. */
  platforms: GnarkPlatformManifest[];
  method: string;
  /** A second resolution of the same tag by another tool on the same host (its raw index bytes' sha256), if any. */
  crossCheck: { tool: string; indexSha256: string } | null;
  observedAtUtc: string;
}

export interface AcquisitionObservation {
  schema: string;
  host: string;
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
  /** The committed production anchor the inspection ran against, from the checkout the tool lives in. */
  anchor: ArchiveAnchor;
  archive: { file: string; bytes: number; sha256: string };
  transfer: TransferProvenance;
  /** sha256 of the same bytes by other implementations on this host (coreutils, OpenSSL, certutil, ...). */
  independentDigests: { tool: string; sha256: string }[];
  /** The merged PA2A inspector's measurement (measuring mode: every entry rule, the required members, d1's key). */
  inspection: {
    members: ArchiveMember[];
    directories: string[];
    metadata: ArchiveMetadata[];
    provenance: Inspection["provenance"];
  };
  /** The census tool's output for this copy: its sha256 (a pure function of the bytes) and its headline counts. */
  census: { schema: string; sha256: string; entries: number; decompressedBytes: number; appleDoubleEntries: number };
  gnark: GnarkObservation;
  /** The host's identity lines (runner image and run id, or the workstation's platform); never a credential. */
  platform: string[];
}

export interface MirrorObservation {
  schema: string;
  host: string;
  measuredAtUtc: string;
  tool: { script: string; scriptSha256: string };
  /** The WalletWall-controlled location as the record will name it (bucket and object, generation included). */
  location: string;
  /** Who controls it and what it is, in words; an assertion the validator records, never verifies. */
  control: string;
  /** The re-read: host (never a signed URL's query), status, window and the bytes it served. */
  fetch: {
    urlHost: string;
    urlPath: string;
    httpCode: number;
    startedAtUtc: string;
    finishedAtUtc: string;
    responseHeaders: { lastModified: string | null; etag: string | null; contentLength: number | null };
  };
  bytes: number;
  sha256: string;
  /** The canonical archive this mirror was checked against, and the verdict of that check. */
  expected: { bytes: number; sha256: string };
  agreement: string;
}

/** The canonical serialization every observation and the record use: what the committed files hold. */
export const serializeJson = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

// ---------------------------------------------------------------------------------------------------------------
// Registry resolution (a tag to its immutable digest), without a pull
// ---------------------------------------------------------------------------------------------------------------

export type Fetch = (url: string, init: { headers: Record<string, string> }) => Promise<Response>;

/** `registry/repository:tag` split; the registry must be a host (fully qualified) and the tag present. */
export function parseTaggedRef(ref: string): { registry: string; repository: string; tag: string } {
  const m =
    /^([a-z0-9.-]+(?::[0-9]+)?)\/([a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*):([A-Za-z0-9_][A-Za-z0-9._-]{0,127})$/.exec(
      ref,
    );
  if (!m || !m[1].includes(".")) throw new Error(`${ref} is not a fully qualified registry/repository:tag reference`);
  return { registry: m[1], repository: m[2], tag: m[3] };
}

async function registryGet(
  fetchImpl: Fetch,
  registry: string,
  repository: string,
  reference: string,
  accept: string,
  token: string | null,
): Promise<{ body: Buffer; headers: Headers; status: number }> {
  const headers: Record<string, string> = { Accept: accept };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetchImpl(`https://${registry}/v2/${repository}/manifests/${reference}`, { headers });
  return { body: Buffer.from(await r.arrayBuffer()), headers: r.headers, status: r.status };
}

/** An anonymous pull token for `repository` (ghcr.io and docker-style registries), or null when none is needed. */
async function anonymousToken(fetchImpl: Fetch, registry: string, repository: string): Promise<string | null> {
  const probe = await fetchImpl(`https://${registry}/v2/`, { headers: {} });
  if (probe.status === 200) return null;
  const challenge = probe.headers.get("www-authenticate") ?? "";
  const realm = /realm="([^"]+)"/.exec(challenge)?.[1];
  const service = /service="([^"]+)"/.exec(challenge)?.[1];
  if (!realm) throw new Error(`${registry} answered ${probe.status} without a bearer challenge`);
  const url = `${realm}?service=${encodeURIComponent(service ?? registry)}&scope=${encodeURIComponent(`repository:${repository}:pull`)}`;
  const r = await fetchImpl(url, { headers: {} });
  if (r.status !== 200) throw new Error(`${realm} refused an anonymous pull token (${r.status})`);
  const t = (await r.json()) as { token?: string; access_token?: string };
  const token = t.token ?? t.access_token;
  if (!token) throw new Error(`${realm} answered without a token`);
  return token;
}

/**
 * Resolves `ref` (registry/repository:tag) to the raw index the registry serves and its digest, then fetches every
 * platform image manifest it lists by digest and re-hashes it. The tag is provenance; the digests are what is
 * recorded. Nothing is pulled: only manifests, a few KB, are read.
 */
export async function resolveImageTag(
  ref: string,
  fetchImpl: Fetch = (url, init) => fetch(url, init),
): Promise<Omit<GnarkObservation, "crossCheck" | "observedAtUtc">> {
  const { registry, repository, tag } = parseTaggedRef(ref);
  const token = await anonymousToken(fetchImpl, registry, repository);
  const index = await registryGet(
    fetchImpl,
    registry,
    repository,
    tag,
    [OCI_INDEX, DOCKER_MANIFEST_LIST, OCI_MANIFEST, DOCKER_MANIFEST].join(", "),
    token,
  );
  if (index.status !== 200) throw new Error(`${ref}: the registry answered ${index.status} for the tag`);
  const digest = `sha256:${sha256(index.body)}`;
  const served = index.headers.get("docker-content-digest") ?? "";
  if (served !== digest) throw new Error(`${ref}: Docker-Content-Digest ${served} is not the bytes' ${digest}`);
  const mediaType = index.headers.get("content-type")?.split(";")[0].trim() ?? "";
  let doc: Record<string, any>;
  try {
    doc = JSON.parse(index.body.toString("utf8"));
  } catch {
    throw new Error(`${ref}: the index is not JSON`);
  }
  if (doc.mediaType !== mediaType || (mediaType !== OCI_INDEX && mediaType !== DOCKER_MANIFEST_LIST)) {
    throw new Error(`${ref}: the tag resolves to ${String(doc.mediaType)}, not a multi-platform index`);
  }
  const manifests: GnarkManifestRef[] = (Array.isArray(doc.manifests) ? doc.manifests : []).map((m: any) => ({
    digest: String(m?.digest),
    mediaType: String(m?.mediaType),
    size: Number(m?.size),
    platform:
      isObject(m?.platform) && isText(m.platform.architecture) && isText(m.platform.os)
        ? {
            architecture: m.platform.architecture,
            os: m.platform.os,
            ...(isText(m.platform.variant) ? { variant: m.platform.variant } : {}),
          }
        : null,
    annotations: isObject(m?.annotations) ? { ...m.annotations } : null,
  }));
  const platforms: GnarkPlatformManifest[] = [];
  for (const m of manifests) {
    if (!m.platform || m.platform.os === "unknown" || m.platform.architecture === "unknown") continue;
    if (!DIGEST.test(m.digest)) throw new Error(`${ref}: a manifest reference has no sha256 digest`);
    const r = await registryGet(fetchImpl, registry, repository, m.digest, m.mediaType, token);
    if (r.status !== 200) throw new Error(`${ref}: the registry answered ${r.status} for ${m.digest}`);
    if (`sha256:${sha256(r.body)}` !== m.digest) throw new Error(`${ref}: ${m.digest} served other bytes`);
    if (r.body.length !== m.size)
      throw new Error(`${ref}: ${m.digest} is ${r.body.length} bytes, the index says ${m.size}`);
    let pm: Record<string, any>;
    try {
      pm = JSON.parse(r.body.toString("utf8"));
    } catch {
      throw new Error(`${ref}: ${m.digest} is not JSON`);
    }
    if (pm.mediaType !== m.mediaType || !isObject(pm.config) || !Array.isArray(pm.layers)) {
      throw new Error(`${ref}: ${m.digest} is not an image manifest`);
    }
    platforms.push({
      digest: m.digest,
      mediaType: m.mediaType,
      platform: m.platform,
      config: { digest: String(pm.config.digest), size: Number(pm.config.size) },
      layers: pm.layers.map((l: any) => ({ digest: String(l?.digest), size: Number(l?.size) })),
    });
  }
  if (platforms.length === 0) throw new Error(`${ref}: the index lists no platform image manifest`);
  return {
    repository: `${registry}/${repository}`,
    tag,
    index: { digest, dockerContentDigest: served, mediaType, bytes: index.body.length, manifests },
    platforms,
    method: REGISTRY_METHOD,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Agreement: every reason a set of observations does not derive one record
// ---------------------------------------------------------------------------------------------------------------

/**
 * What the committed census of the upstream archive says about its bytes: the archive's length and sha256, every
 * regular member (path, length, sha256) and every AppleDouble entry. The census was taken on two hosts and merged with
 * the PA2A amendment: it is the independently reviewed fact an acquisition observation must match, so a pair of
 * observations forged consistently with each other still names another archive than the one the repository censused.
 */
export interface CensusFacts {
  /** sha256 of the census tool's output: what each observation's own census of its copy must hash to. */
  sha256: string;
  archive: { bytes: number; sha256: string };
  members: ArchiveMember[];
  metadata: { path: string; bytes: number; sha256: string }[];
}

export interface AcquisitionExpectations {
  anchor: ArchiveAnchor;
  /** The gnark image the pinned prover defaults to (repository:tag), from the proving-artifacts observation. */
  gnarkImage: string;
  /** The committed census (both PA2A census files are this one census). */
  census: CensusFacts;
  /** sha256 of the committed measurement scripts (null when a script is absent: then nothing binds). */
  scripts: { acquisition: string | null; mirror: string | null };
}

const EXPECTED_DIRECTORIES: readonly string[] = [];
const byPath = <T extends { path: string }>(xs: readonly T[]) => [...xs].sort((a, b) => (a.path < b.path ? -1 : 1));
const censusPath = (p: string) => (p.startsWith("./") ? p.slice(2) : p).replace(/\/+$/, "");
const isAppleDoubleShaped = (path: string): boolean => path.split("/").some((p) => p.startsWith("._"));

/** The facts a census states about the archive it walked; throws when `census` is not a census. */
export function censusFacts(census: unknown, serialized: string): CensusFacts {
  const c = census as Census;
  if (!isObject(c) || c.schema !== CENSUS_SCHEMA || !isObject(c.archive) || !Array.isArray(c.entries)) {
    throw new Error(`the committed census is not ${CENSUS_SCHEMA}`);
  }
  const members = c.entries
    .filter((e) => e.typeflag === "0" && !isAppleDoubleShaped(censusPath(e.path)) && censusPath(e.path) !== "")
    .map((e) => ({ path: censusPath(e.path), bytes: e.size, sha256: e.dataSha256 }));
  const metadata = (Array.isArray(c.appleDouble) ? c.appleDouble : []).map((r) => ({
    path: r.path,
    bytes: r.size,
    sha256: r.sha256,
  }));
  return {
    sha256: sha256(serialized),
    archive: { bytes: c.archive.bytes, sha256: c.archive.sha256 },
    members: byPath(members),
    metadata: byPath(metadata),
  };
}

/** A shape check: `o` must name exactly `keys`; reports the extra and missing ones under `reason`. */
function exactly(
  o: unknown,
  keys: readonly string[],
  where: string,
  reason: string,
  no: (reason: string, detail: string) => void,
): o is Record<string, any> {
  if (!isObject(o)) {
    no(reason, `${where} is not an object`);
    return false;
  }
  const extra = Object.keys(o).filter((k) => !keys.includes(k));
  const missing = keys.filter((k) => !(k in o));
  if (extra.length > 0) no(reason, `${where} names ${extra.join(", ")}`);
  if (missing.length > 0) no(reason, `${where} lacks ${missing.join(", ")}`);
  return extra.length === 0 && missing.length === 0;
}

function transferErrors(t: unknown, i: number, no: (reason: string, detail: string) => void): void {
  const where = `observations[${i}].transfer`;
  if (!isObject(t)) return no("OBSERVATION_SHAPE", `${where} is not an object`);
  if (urlHost(t.sourceUrl) === null) no("TRANSFER_FIELD", `${where}.sourceUrl is not https`);
  if (urlHost(t.urlEffective) === null) no("TRANSFER_FIELD", `${where}.urlEffective is not https`);
  if (t.httpCode !== 200) no("TRANSFER_INCOMPLETE", `${where} ended with HTTP ${String(t.httpCode)}, not 200`);
  if (!isText(t.remoteIp)) no("TRANSFER_FIELD", `${where}.remoteIp`);
  if (!(typeof t.timeTotalSeconds === "number" && t.timeTotalSeconds > 0))
    no("TRANSFER_FIELD", `${where}.timeTotalSeconds`);
  if (!UTC.test(String(t.startedAtUtc)) || !UTC.test(String(t.finishedAtUtc)) || t.startedAtUtc > t.finishedAtUtc) {
    no("TRANSFER_FIELD", `${where}: the transfer window is not two ordered UTC timestamps`);
  }
  const h = t.responseHeaders;
  if (!isObject(h) || !["lastModified", "etag", "contentLength", "server"].every((k) => k in h)) {
    no("TRANSFER_FIELD", `${where}.responseHeaders is incomplete`);
  }
}

/** Every reason `value` is not an acquisition observation whose copy is exactly `expect`'s archive; [] accepts it. */
export function acquisitionObservationErrors(
  value: unknown,
  i: number,
  expect: AcquisitionExpectations,
): { reason: string; detail: string }[] {
  const out: { reason: string; detail: string }[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const where = `observations[${i}]`;
  if (!exactly(value, OBSERVATION_FIELDS.acquisition, where, "OBSERVATION_SHAPE", no)) return out;
  const o = value as AcquisitionObservation;
  if (o.schema !== ACQUISITION_SCHEMA) no("OBSERVATION_SCHEMA", `${where} must be ${ACQUISITION_SCHEMA}`);
  if (!HOST_LABEL.test(String(o.host))) no("OBSERVATION_HOST", `${where}.host is not a host label`);
  if (!UTC.test(String(o.measuredAtUtc))) no("OBSERVATION_FIELD", `${where}.measuredAtUtc`);
  if (
    !exactly(o.tool, OBSERVATION_FIELDS.tool, `${where}.tool`, "OBSERVATION_SHAPE", no) ||
    o.tool.script !== ACQUISITION_SCRIPT_REL ||
    expect.scripts.acquisition === null ||
    o.tool.scriptSha256 !== expect.scripts.acquisition
  ) {
    no("TOOL_NOT_BOUND", `${where} was not made by ${ACQUISITION_SCRIPT_REL} as committed: re-measure`);
  }
  if (!same(o.anchor, expect.anchor)) no("ANCHOR_MISMATCH", `${where} measured against another anchor than d1's`);
  const a = o.archive;
  if (
    !exactly(a, OBSERVATION_FIELDS.archive, `${where}.archive`, "OBSERVATION_SHAPE", no) ||
    !/^[A-Za-z0-9._-]+\.tar\.gz$/.test(String(a.file)) ||
    !isCount(a.bytes) ||
    a.bytes === 0 ||
    !HEX64.test(String(a.sha256))
  ) {
    no("ARCHIVE_FIELD", `${where}.archive is not a measured file, length and sha256`);
  }
  if (isObject(a) && a.file !== `${expect.anchor.circuitVersion}-groth16.tar.gz`) {
    no(
      "ARCHIVE_FIELD",
      `${where}.archive.file ${String(a.file)} is not the ${expect.anchor.circuitVersion} Groth16 archive`,
    );
  }
  // The copy is the archive the repository censused: its length and sha256 are the committed census's, not merely
  // what two observations agree on between themselves.
  if (isObject(a) && (a.bytes !== expect.census.archive.bytes || a.sha256 !== expect.census.archive.sha256)) {
    no(
      "CENSUS_MISMATCH",
      `${where}: ${String(a.bytes)} bytes, sha256 ${String(a.sha256)} is not the archive the committed census observed (${expect.census.archive.bytes} bytes, sha256 ${expect.census.archive.sha256})`,
    );
  }
  if (exactly(o.transfer, OBSERVATION_FIELDS.transfer, `${where}.transfer`, "OBSERVATION_SHAPE", no)) {
    transferErrors(o.transfer, i, no);
  }
  if (isObject(o.transfer) && isObject(a)) {
    const t = o.transfer;
    if (typeof t.urlEffective === "string" && !t.urlEffective.endsWith(`/${a.file}`)) {
      no("TRANSFER_FIELD", `${where}: the transfer did not end at /${String(a.file)}`);
    }
    const cl = t.responseHeaders?.contentLength;
    if (cl !== null && cl !== undefined && cl !== a.bytes) {
      no("TRANSFER_INCOMPLETE", `${where}: Content-Length ${String(cl)} is not the ${String(a.bytes)} bytes measured`);
    }
    if (!(t.finishedAtUtc <= o.measuredAtUtc))
      no("OBSERVATION_FIELD", `${where} was measured before its transfer ended`);
  }
  const digests = Array.isArray(o.independentDigests) ? o.independentDigests : null;
  if (!digests || digests.length < 2) {
    no(
      "DIGESTS_NOT_INDEPENDENT",
      `${where} needs at least two independent digest implementations besides the inspector`,
    );
  } else {
    const tools = new Set<string>();
    digests.forEach((d, k) => {
      if (!isText(d?.tool) || tools.has(d.tool))
        no("DIGESTS_NOT_INDEPENDENT", `${where}.independentDigests[${k}] tool`);
      tools.add(String(d?.tool));
      if (d?.sha256 !== a?.sha256) no("DIGEST_DISAGREES", `${where}: ${String(d?.tool)} measured ${String(d?.sha256)}`);
    });
  }
  const ins = o.inspection;
  if (
    !isObject(ins) ||
    !Array.isArray(ins.members) ||
    !Array.isArray(ins.directories) ||
    !Array.isArray(ins.metadata) ||
    !Array.isArray(ins.provenance)
  ) {
    no("INSPECTION_MISSING", `${where} holds no inspection: the inspector refused this copy, or it was never run`);
  } else {
    exactly(ins, OBSERVATION_FIELDS.inspection, `${where}.inspection`, "OBSERVATION_SHAPE", no);
    if (ins.members.length === 0) no("INSPECTION_MISSING", `${where}: the inspection names no member`);
    if (!same(ins.directories, EXPECTED_DIRECTORIES)) no("INSPECTION_FIELD", `${where}: the archive holds directories`);
    const vk = ins.members.find((m) => m?.path === VK_FILE);
    if (
      !vk ||
      `0x${vk.sha256}` !== expect.anchor.verifyingKey.sha256 ||
      vk.bytes !== expect.anchor.verifyingKey.bytes
    ) {
      no("VK_MISMATCH", `${where}: ${VK_FILE} is not the designated verifying key`);
    }
    // Every member and every AppleDouble entry the inspector measured is one the committed census listed, with its
    // length and sha256, and none is missing: the member set is the census's, never the observation's own.
    const members = byPath(ins.members.map((m) => ({ path: m?.path, bytes: m?.bytes, sha256: m?.sha256 })));
    if (!same(members, expect.census.members)) {
      no("CENSUS_MISMATCH", `${where}: the members measured are not the members the committed census listed`);
    }
    const metadata = byPath(ins.metadata.map((m) => ({ path: m?.path, bytes: m?.bytes, sha256: m?.sha256 })));
    if (!same(metadata, expect.census.metadata)) {
      no("CENSUS_MISMATCH", `${where}: the AppleDouble entries measured are not the committed census's`);
    }
  }
  const c = o.census;
  if (
    !exactly(c, OBSERVATION_FIELDS.census, `${where}.census`, "OBSERVATION_SHAPE", no) ||
    !HEX64.test(String(c.sha256)) ||
    !isCount(c.entries) ||
    !isCount(c.decompressedBytes) ||
    !isCount(c.appleDoubleEntries)
  ) {
    no("CENSUS_MISSING", `${where} holds no census`);
  } else if (c.sha256 !== expect.census.sha256) {
    no(
      "CENSUS_MISMATCH",
      `${where}: the census of this copy (${c.sha256}) is not the committed census (${expect.census.sha256})`,
    );
  }
  if (exactly(o.gnark, OBSERVATION_FIELDS.gnark, `${where}.gnark`, "OBSERVATION_SHAPE", no)) {
    gnarkErrors(o.gnark, where, expect.gnarkImage, no);
  }
  if (!Array.isArray(o.platform) || !o.platform.every(isText) || o.platform.length === 0) {
    no("OBSERVATION_FIELD", `${where}.platform names no host identity`);
  } else {
    const marker = HOST_IDENTITY_MARKERS[String(o.host)];
    if (marker && !o.platform.some((line) => marker.test(line))) {
      no("OBSERVATION_FIELD", `${where}.platform carries no ${String(marker)} line, which ${String(o.host)} records`);
    }
  }
  return out;
}

/** Called only for an object: the caller's closed-shape check refuses anything else before this runs. */
function gnarkErrors(
  g: Record<string, any>,
  where: string,
  image: string,
  no: (reason: string, detail: string) => void,
): void {
  const { registry, repository, tag } = (() => {
    try {
      return parseTaggedRef(image);
    } catch {
      return { registry: "", repository: "", tag: "" };
    }
  })();
  if (g.repository !== `${registry}/${repository}` || g.tag !== tag) {
    no(
      "GNARK_IMAGE_MISMATCH",
      `${where}: ${String(g.repository)}:${String(g.tag)} is not the pinned prover's ${image}`,
    );
  }
  const idx = g.index;
  // imageRefError refuses a malformed digest (MALFORMED_DIGEST) as well as a tag, an unqualified or malformed
  // repository: it is the one check, the same the prove gate applies to SP1_GNARK_IMAGE.
  if (!isObject(idx) || imageRefError(`${String(g.repository)}@${String(idx.digest)}`) !== null) {
    no("GNARK_NOT_DIGEST_PINNED", `${where}: the tag was not resolved to registry/repository@sha256:<digest>`);
    return;
  }
  if (idx.dockerContentDigest !== idx.digest)
    no("GNARK_DIGEST_UNCONFIRMED", `${where}: Docker-Content-Digest differs from the bytes' digest`);
  if (idx.mediaType !== OCI_INDEX && idx.mediaType !== DOCKER_MANIFEST_LIST) {
    no("GNARK_NOT_AN_INDEX", `${where}: the tag resolves to ${String(idx.mediaType)}`);
  }
  if (!isCount(idx.bytes) || idx.bytes === 0 || !Array.isArray(idx.manifests))
    no("GNARK_FIELD", `${where}.gnark.index`);
  const amd64 = (Array.isArray(idx.manifests) ? idx.manifests : []).filter(
    (m: GnarkManifestRef) =>
      m?.platform?.architecture === LINUX_AMD64.architecture && m?.platform?.os === LINUX_AMD64.os,
  );
  if (amd64.length !== 1)
    no("GNARK_PLATFORM_AMBIGUOUS", `${where}: the index lists ${amd64.length} linux/amd64 manifests`);
  const platforms = Array.isArray(g.platforms) ? (g.platforms as GnarkPlatformManifest[]) : [];
  const fetched = platforms.find(
    (p) => p?.platform?.architecture === LINUX_AMD64.architecture && p?.platform?.os === LINUX_AMD64.os,
  );
  if (!fetched || !amd64[0] || fetched.digest !== amd64[0].digest || !DIGEST.test(String(fetched.config?.digest))) {
    no("GNARK_PLATFORM_UNRESOLVED", `${where}: the linux/amd64 image manifest was not fetched by its digest`);
  }
  if (g.method !== REGISTRY_METHOD) no("GNARK_METHOD", `${where}: the resolution method is not the registry read`);
  if (
    g.crossCheck !== null &&
    (!isObject(g.crossCheck) ||
      !isText(g.crossCheck.tool) ||
      `sha256:${String(g.crossCheck.indexSha256)}` !== idx.digest)
  ) {
    no("GNARK_CROSS_CHECK_DISAGREES", `${where}: the second resolution of the tag gave another index`);
  }
  if (!UTC.test(String(g.observedAtUtc))) no("GNARK_FIELD", `${where}.gnark.observedAtUtc`);
}

/** Every reason `value` is not a mirror observation of the archive `archive`; [] accepts it. */
export function mirrorObservationErrors(
  value: unknown,
  i: number,
  archive: { bytes: number; sha256: string; upstreamHost: string },
  scriptSha256: string | null,
): { reason: string; detail: string }[] {
  const out: { reason: string; detail: string }[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  const where = `mirrors[${i}]`;
  if (!exactly(value, OBSERVATION_FIELDS.mirror, where, "MIRROR_SHAPE", no)) return out;
  const m = value as MirrorObservation;
  if (m.schema !== MIRROR_SCHEMA) no("MIRROR_SCHEMA", `${where} must be ${MIRROR_SCHEMA}`);
  if (!HOST_LABEL.test(String(m.host))) no("MIRROR_FIELD", `${where}.host is not a host label`);
  if (!UTC.test(String(m.measuredAtUtc))) no("MIRROR_FIELD", `${where}.measuredAtUtc`);
  if (
    !exactly(m.tool, OBSERVATION_FIELDS.tool, `${where}.tool`, "MIRROR_SHAPE", no) ||
    m.tool.script !== MIRROR_SCRIPT_REL ||
    scriptSha256 === null ||
    m.tool.scriptSha256 !== scriptSha256
  ) {
    no("TOOL_NOT_BOUND", `${where} was not made by ${MIRROR_SCRIPT_REL} as committed: re-measure`);
  }
  const identity = isText(m.location) ? mirrorIdentity(m.location) : null;
  if (identity === null) {
    no(
      "MIRROR_FIELD",
      `${where}.location ${JSON.stringify(m.location)} is not a WalletWall mirror location (gs://<bucket>/<object> or r2://<account>/<bucket>/<object>, no query, fragment or credential)`,
    );
  }
  if (!isText(m.control)) no("MIRROR_FIELD", `${where}.control names no controller`);
  const f = m.fetch;
  if (
    !exactly(f, OBSERVATION_FIELDS.fetch, `${where}.fetch`, "MIRROR_SHAPE", no) ||
    !isText(f.urlHost) ||
    !isText(f.urlPath) ||
    !UTC.test(String(f.startedAtUtc)) ||
    !UTC.test(String(f.finishedAtUtc)) ||
    !isObject(f.responseHeaders)
  ) {
    no("MIRROR_FIELD", `${where}.fetch is incomplete`);
  } else {
    if (f.httpCode !== 200) no("MIRROR_INCOMPLETE", `${where}: the re-read ended with HTTP ${String(f.httpCode)}`);
    // The upstream host itself, or any host under its registrable domain (a CDN alias, say).
    if (registrableDomain(f.urlHost) === registrableDomain(archive.upstreamHost)) {
      no("MIRROR_IS_UPSTREAM", `${where} re-read ${f.urlHost}, the upstream source, which is no WalletWall mirror`);
    }
    if (f.urlPath.includes("?") || f.urlPath.includes("#") || !f.urlPath.startsWith("/")) {
      no("MIRROR_FIELD", `${where}.fetch.urlPath is not a plain path (a signed URL is never recorded)`);
    }
    const served = fetchIdentity(f.urlHost, f.urlPath);
    if (served === null) {
      no(
        "MIRROR_HOST_UNKNOWN",
        `${where} re-read ${f.urlHost}, which is no host of ${MIRROR_PROVIDERS.map((p) => p.id).join(" or ")}: not a WalletWall mirror location`,
      );
    } else if (identity !== null && served !== identity) {
      no("MIRROR_LOCATION_MISMATCH", `${where} re-read ${served}, not its location ${identity}`);
    }
    const cl = f.responseHeaders.contentLength;
    if (cl !== null && cl !== undefined && cl !== archive.bytes)
      no("MIRROR_INCOMPLETE", `${where}: Content-Length ${String(cl)}`);
    if (!(f.finishedAtUtc <= m.measuredAtUtc)) no("MIRROR_FIELD", `${where} was measured before its re-read ended`);
  }
  if (m.bytes !== archive.bytes || m.sha256 !== archive.sha256) {
    no("MIRROR_DISAGREES", `${where} holds ${String(m.bytes)} bytes, sha256 ${String(m.sha256)}: not the archive`);
  }
  if (
    !exactly(m.expected, OBSERVATION_FIELDS.expected, `${where}.expected`, "MIRROR_SHAPE", no) ||
    !same(m.expected, { bytes: archive.bytes, sha256: archive.sha256 }) ||
    m.agreement !== AGREES
  ) {
    no("MIRROR_DISAGREES", `${where} was not checked against the archive, or did not agree`);
  }
  return out;
}

/** The last two labels of a host: the domain an alias of the upstream bucket still sits under (good enough here). */
export function registrableDomain(host: string): string {
  return host.toLowerCase().split(".").slice(-2).join(".");
}

const OBJECT_SEGMENT = /^[^/?#\s]+$/;
const BUCKET = /^[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]$/;
const R2_ACCOUNT = /^[a-f0-9]{32}$/;
/** Each path segment percent-decoded (a decoding that fails, or decodes to a separator, names no object). */
function decodedSegments(path: string): string[] | null {
  const segments = path.split("/");
  const out: string[] = [];
  for (const s of segments) {
    if (!OBJECT_SEGMENT.test(s)) return null;
    let d: string;
    try {
      d = decodeURIComponent(s);
    } catch {
      return null;
    }
    if (d.includes("/") || d.includes("\\") || d.trim() !== d || d === "" || d === "." || d === "..") return null;
    out.push(d);
  }
  return out;
}

/**
 * The object a mirror location names, canonically (`gcs:<bucket>/<object>`, `r2:<account>/<bucket>/<object>`), or
 * null when the location is not exactly a provider's grammar: a query, a fragment, a credential, an empty or dotted
 * segment, an upper-case bucket, another scheme. The object key keeps its case (object stores are case-sensitive).
 */
export function mirrorIdentity(location: string): string | null {
  const m = /^([a-z0-9]+):\/\/(.+)$/.exec(location);
  // A query, a fragment or whitespace is refused by the segment grammar below; a credential marker is refused here.
  if (!m || location.includes("@")) return null;
  const provider = MIRROR_PROVIDERS.find((p) => p.scheme === m[1]);
  if (!provider) return null;
  const segments = decodedSegments(m[2]);
  if (segments === null || segments.length < provider.segments + 1) return null;
  const head = segments.slice(0, provider.segments);
  const key = segments.slice(provider.segments).join("/");
  if (provider.id === "gcs" && !BUCKET.test(head[0])) return null;
  if (provider.id === "r2" && (!R2_ACCOUNT.test(head[0]) || !BUCKET.test(head[1]))) return null;
  return `${provider.id}:${head.join("/")}/${key}`;
}

/**
 * The object a re-read's host and path name, canonically, under the providers' addressing styles: path-style on the
 * provider host (`storage.googleapis.com/<bucket>/<object>`, `<account>.r2.cloudflarestorage.com/<bucket>/<object>`)
 * or virtual-hosted on a bucket subdomain; null for any other host.
 */
export function fetchIdentity(host: string, path: string): string | null {
  const h = host.toLowerCase().replace(/:443$/, "");
  const segments = decodedSegments(path.replace(/^\//, ""));
  if (segments === null) return null;
  for (const p of MIRROR_PROVIDERS) {
    const m = p.host.exec(h);
    if (!m) continue;
    if (p.id === "gcs") {
      const bucket = m[1];
      const [b, ...key] = bucket === undefined ? segments : [bucket, ...segments];
      if (!b || !BUCKET.test(b) || key.length === 0) return null;
      return `gcs:${b}/${key.join("/")}`;
    }
    const [bucketLabel, account] = [m[1], m[2]];
    const [b, ...key] = bucketLabel === undefined ? segments : [bucketLabel, ...segments];
    if (!b || !BUCKET.test(b) || key.length === 0) return null;
    return `r2:${account}/${b}/${key.join("/")}`;
  }
  return null;
}

/**
 * Every reason `observations` (one per host) and `mirrors` do not derive one archive record for `expect`'s anchor:
 * each observation on its own, then the hosts against each other (distinct labels; the same bytes, inspection,
 * census and image), then the mirrors (distinct locations, never upstream, each the archive's bytes).
 */
export function acquisitionErrors(
  observations: readonly unknown[],
  mirrors: readonly unknown[],
  expect: AcquisitionExpectations,
): { reason: string; detail: string }[] {
  const out: { reason: string; detail: string }[] = [];
  const no = (reason: string, detail: string) => out.push({ reason, detail });
  if (observations.length < MIN_ACQUISITIONS) {
    no(
      "ACQUISITIONS_MISSING",
      `${observations.length} acquisition observation(s); at least ${MIN_ACQUISITIONS} hosts are required`,
    );
  }
  observations.forEach((o, i) => out.push(...acquisitionObservationErrors(o, i, expect)));
  if (out.length > 0) return out;
  const obs = observations as AcquisitionObservation[];
  const hosts = new Set<string>();
  for (const o of obs) {
    if (hosts.has(o.host)) no("ACQUISITION_NOT_INDEPENDENT", `host ${o.host} is counted twice`);
    hosts.add(o.host);
  }
  if ([...hosts].sort().join() !== [...ACQUISITION_HOSTS].sort().join()) {
    no("ACQUISITION_HOSTS_MISMATCH", `the hosts are ${[...hosts].join(", ")}, not ${ACQUISITION_HOSTS.join(" and ")}`);
  }
  // Two observations of one acquisition relabeled as two hosts share what two machines cannot: the transfer (its
  // remote address and window), the measurement and resolution times, or the identity lines.
  obs.forEach((o, k) =>
    obs.slice(0, k).forEach((p, j) => {
      const shared: string[] = [];
      if (
        o.transfer.remoteIp === p.transfer.remoteIp &&
        o.transfer.startedAtUtc === p.transfer.startedAtUtc &&
        o.transfer.finishedAtUtc === p.transfer.finishedAtUtc
      ) {
        shared.push("the transfer's remote address and window");
      }
      if (o.measuredAtUtc === p.measuredAtUtc) shared.push("the measurement time");
      if (o.gnark.observedAtUtc === p.gnark.observedAtUtc) shared.push("the image resolution time");
      if (same(o.platform, p.platform)) shared.push("the identity lines");
      if (shared.length > 0) {
        no(
          "ACQUISITION_NOT_INDEPENDENT",
          `observations[${k}] (${o.host}) repeats observations[${j}]'s (${p.host}) ${shared.join(", ")}: one acquisition under two labels`,
        );
      }
    }),
  );
  // Every observation passed its own checks above, which already bind three facts to constants on every host: the
  // archive's file name (the anchor's circuit version), its length and sha256 (the committed census's) and the
  // census itself. Those cannot differ between hosts that both passed, so only the facts no constant binds (the
  // URL, the inspection, the image) are compared here.
  const first = obs[0];
  obs.slice(1).forEach((o, k) => {
    const where = `observations[${k + 1}] (${o.host})`;
    if (o.transfer.urlEffective !== first.transfer.urlEffective)
      no("HOSTS_DISAGREE", `${where} acquired from another URL`);
    if (!same(o.inspection, first.inspection))
      no("HOSTS_DISAGREE", `${where}: the inspection differs from ${first.host}'s`);
    if (o.gnark.index.digest !== first.gnark.index.digest)
      no("HOSTS_DISAGREE", `${where}: the tag resolved to another index than on ${first.host}`);
    if (!same(o.gnark.platforms, first.gnark.platforms))
      no("HOSTS_DISAGREE", `${where}: the platform manifests differ from ${first.host}'s`);
  });
  const upstreamHost = urlHost(first.transfer.urlEffective) ?? "";
  const archive = { bytes: first.archive.bytes, sha256: first.archive.sha256, upstreamHost };
  if (mirrors.length < MIN_MIRRORS) {
    no(
      "MIRRORS_MISSING",
      `${mirrors.length} mirror observation(s); at least ${MIN_MIRRORS} WalletWall-controlled locations are required`,
    );
  }
  mirrors.forEach((m, i) => out.push(...mirrorObservationErrors(m, i, archive, expect.scripts.mirror)));
  // Distinct objects, not distinct spellings: the canonical identity of each location (its re-read was held to the
  // same identity above), so one object under two addressing styles, spellings or versions is one mirror.
  const seen = new Map<string, number>();
  (mirrors as MirrorObservation[]).forEach((m, i) => {
    const key = (isText(m?.location) ? mirrorIdentity(m.location) : null) ?? `#${i}`;
    const prior = seen.get(key);
    if (prior !== undefined) no("MIRRORS_NOT_DISTINCT", `mirrors[${i}] and mirrors[${prior}] name one object (${key})`);
    seen.set(key, i);
  });
  return out;
}

/** The record `observations` and `mirrors` derive; throws naming every reason when they derive none. */
export function deriveArchiveRecord(
  observations: readonly unknown[],
  mirrors: readonly unknown[],
  expect: AcquisitionExpectations,
): ArchiveRecord {
  const errors = acquisitionErrors(observations, mirrors, expect);
  if (errors.length > 0) {
    throw new Error(
      `the observations derive no archive record:\n - ${errors.map((e) => `${e.reason}: ${e.detail}`).join("\n - ")}`,
    );
  }
  const obs = [...(observations as AcquisitionObservation[])].sort((a, b) => (a.host < b.host ? -1 : 1));
  const ms = [...(mirrors as MirrorObservation[])].sort((a, b) => (a.location < b.location ? -1 : 1));
  const first = obs[0];
  const byPath = <T extends { path: string }>(xs: readonly T[]) => [...xs].sort((a, b) => (a.path < b.path ? -1 : 1));
  const amd64 = first.gnark.platforms.find((p) => p.platform.architecture === "amd64" && p.platform.os === "linux");
  const a = expect.anchor;
  return {
    schema: ARCHIVE_RECORD_SCHEMA,
    subject: {
      circuitSystem: CIRCUIT_SYSTEM,
      circuitVersion: a.circuitVersion,
      designation: a.designation,
      programVKey: a.programVKey,
      verifier: { ...a.verifier },
      verifyingKey: { file: VK_FILE, sha256: a.verifyingKey.sha256, bytes: a.verifyingKey.bytes },
    },
    archive: {
      file: first.archive.file,
      format: ARCHIVE_FORMAT,
      bytes: first.archive.bytes,
      sha256: first.archive.sha256,
      acquiredAtUtc: obs.map((o) => o.transfer.finishedAtUtc).sort()[0],
      sourceUrl: first.transfer.urlEffective,
      sourceUrlRole: PROVENANCE_ONLY,
    },
    acquisitions: obs.map((o) => ({
      host: o.host,
      observedAtUtc: o.transfer.finishedAtUtc,
      bytes: o.archive.bytes,
      sha256: o.archive.sha256,
      agreement: AGREES,
    })),
    members: byPath(first.inspection.members).map((m) => ({ path: m.path, bytes: m.bytes, sha256: m.sha256 })),
    metadata: byPath(first.inspection.metadata).map((m) => ({ ...m })),
    gnark: {
      repository: first.gnark.repository,
      tag: first.gnark.tag,
      tagRole: PROVENANCE_ONLY,
      digest: first.gnark.index.digest,
      observation: {
        host: first.host,
        observedAtUtc: first.gnark.observedAtUtc,
        method: `${first.gnark.method}; the index is ${first.gnark.index.mediaType} and its linux/amd64 image manifest is ${String(amd64?.digest)} (config ${String(amd64?.config.digest)}); resolved identically on ${obs.map((o) => o.host).join(" and ")}`,
      },
      mirror: null,
    },
    mirrors: ms.map((m) => ({ location: m.location, sha256: m.sha256 })),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The committed evidence
// ---------------------------------------------------------------------------------------------------------------

/** The production record's path for `anchor`'s circuit: one file, named after the archive. */
export const productionRecordRel = (anchor: ArchiveAnchor) =>
  `${PROVING_ARCHIVES_DIR}/${anchor.circuitVersion}-groth16.json`;

/** The committed mirror observations, sorted by file name. */
export function mirrorObservationsIn(repoRoot = "."): string[] {
  const dir = resolve(repoRoot, OBSERVATIONS_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.startsWith(MIRROR_OBSERVATION_PREFIX) && f.endsWith(".raw.json"))
    .sort()
    .map((f) => `${OBSERVATIONS_DIR}/${f}`);
}

export interface ArchiveEvidence {
  /** Every file under PROVING_ARCHIVES_DIR, as archiveRecordsIn lists them. */
  records: string[];
  /** The one accepted record, derived from the committed observations and equal to the committed file; else null. */
  record: ArchiveRecord | null;
  /** The acquisition and mirror observation paths the record was derived from (empty while there is no record). */
  observations: string[];
  errors: string[];
}

export interface ArchiveEvidenceInput {
  anchor: ArchiveAnchor;
  gnarkImage: string;
}

function readJson(repoRoot: string, rel: string): unknown {
  return JSON.parse(readFileSync(resolve(repoRoot, rel), "utf8"));
}

/** The acquisition expectations the repository holds for `input`'s anchor (the committed census and scripts). */
export function acquisitionExpectations(repoRoot: string, input: ArchiveEvidenceInput): AcquisitionExpectations {
  const censusText = readFileSync(resolve(repoRoot, CENSUS_OBSERVATIONS_REL[0]), "utf8").replace(/\r\n/g, "\n");
  const census = JSON.parse(censusText) as unknown;
  // A script is bound by the sha256 of its LF bytes (what the tool computes of itself on an LF checkout, and what git
  // commits); a checkout that converts line endings still binds, and an absent script binds nothing.
  const scriptSha = (rel: string): string | null => {
    const p = resolve(repoRoot, rel);
    return existsSync(p) ? sha256(readFileSync(p, "utf8").replace(/\r\n/g, "\n")) : null;
  };
  return {
    anchor: input.anchor,
    gnarkImage: input.gnarkImage,
    census: censusFacts(census, serializeJson(census)),
    scripts: { acquisition: scriptSha(ACQUISITION_SCRIPT_REL), mirror: scriptSha(MIRROR_SCRIPT_REL) },
  };
}

/**
 * What the repository holds under PROVING_ARCHIVES_DIR, judged: no record (the state before an acquisition lane), or
 * exactly one record that is byte for byte the record the committed acquisition and mirror observations derive, is
 * accepted by the record validator for the anchor, and is committed with its observations exactly as HEAD commits
 * them. Anything else (a second file, a record without its observations, a hand-edited record, an uncommitted one) is
 * refused with every reason, and never read as "no record".
 */
export function productionArchiveEvidence(repoRoot: string, input: ArchiveEvidenceInput): ArchiveEvidence {
  const records = archiveRecordsIn(repoRoot);
  if (records.length === 0) return { records, record: null, observations: [], errors: [] };
  const errors: string[] = [];
  const want = productionRecordRel(input.anchor);
  if (records.length !== 1 || records[0] !== want) {
    errors.push(`${PROVING_ARCHIVES_DIR} must hold exactly ${want}; it holds ${records.join(", ")}`);
  }
  // The record is a regular file in the directory itself, as the gate's authoritativeRecordError reads it: a link
  // placed there, wherever it points, is no record, so the state and the gate never disagree.
  for (const rel of records) {
    const full = resolve(repoRoot, rel);
    let regular = false;
    try {
      regular =
        lstatSync(full).isFile() &&
        dirname(realpathSync(full)) === realpathSync(resolve(repoRoot, PROVING_ARCHIVES_DIR));
    } catch {
      regular = false;
    }
    if (!regular) errors.push(`${rel} is not a regular file directly in ${PROVING_ARCHIVES_DIR}`);
  }
  const observations = [...ACQUISITION_OBSERVATIONS_REL, ...mirrorObservationsIn(repoRoot)];
  const absent = observations.filter((rel) => !existsSync(resolve(repoRoot, rel)));
  if (absent.length > 0) errors.push(`acquisition observations are missing: ${absent.join(", ")}`);
  if (errors.length > 0) return { records, record: null, observations, errors };
  const expect = acquisitionExpectations(repoRoot, input);
  const acquisitions = ACQUISITION_OBSERVATIONS_REL.map((rel) => readJson(repoRoot, rel));
  // Each observation file is one host's, by name: the host it claims must be the host the file is for.
  acquisitions.forEach((o, i) => {
    const host = (o as { host?: unknown })?.host;
    if (host !== ACQUISITION_HOSTS[i]) {
      errors.push(`${ACQUISITION_OBSERVATIONS_REL[i]} claims host ${String(host)}, not ${ACQUISITION_HOSTS[i]}`);
    }
  });
  if (errors.length > 0) return { records, record: null, observations, errors };
  const mirrors = mirrorObservationsIn(repoRoot).map((rel) => readJson(repoRoot, rel));
  const agreement = acquisitionErrors(acquisitions, mirrors, expect);
  if (agreement.length > 0) {
    return {
      records,
      record: null,
      observations,
      errors: agreement.map((e) => `${e.reason}: ${e.detail}`),
    };
  }
  const derived = deriveArchiveRecord(acquisitions, mirrors, expect);
  const recordErrors = archiveRecordErrors(derived, input.anchor);
  if (recordErrors.length > 0)
    errors.push(...recordErrors.map((e) => `derived record refused: ${e.reason}: ${e.detail}`));
  const text = readFileSync(resolve(repoRoot, records[0]), "utf8").replace(/\r\n/g, "\n");
  if (text !== serializeJson(derived)) {
    errors.push(
      `${records[0]} is not the record the committed observations derive: regenerate it (npm run sp1:proving-archive-record)`,
    );
  }
  const dirty = uncommittedEvidenceError([...records, ...observations], repoRoot);
  if (dirty !== null) errors.push(`the archive evidence is not as committed: ${dirty}`);
  return { records, record: errors.length === 0 ? derived : null, observations, errors };
}

/** The state the archive evidence is in, as the tooling record names it. */
export function archiveEvidenceState(e: ArchiveEvidence): "NO_RECORD" | "ACCEPTED" | "REFUSED" {
  if (e.records.length === 0) return e.errors.length === 0 ? "NO_RECORD" : "REFUSED";
  return e.record !== null && e.errors.length === 0 ? "ACCEPTED" : "REFUSED";
}
