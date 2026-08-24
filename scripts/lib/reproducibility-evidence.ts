/**
 * Deterministic, offline replay of a deployment-reproducibility claim from a
 * committed evidence bundle.
 *
 * A reproducibility manifest (deployments/reproducibility/*.json) previously
 * carried hand-set booleans (`executableBytecodeMatch`,
 * `immutableValuesIndependentlyVerified`, `bytecodeHash`, ...) that the
 * validator only format-checked — nothing re-derived them. This module makes
 * those facts REPLAYABLE: given a committed evidence bundle, every one of
 * those facts is recomputed from scratch, and the manifest's own claims are
 * cross-checked against the recomputation. No field in the manifest — and no
 * field WITHIN the evidence bundle that could itself be self-asserted — is
 * ever trusted as its own authority; see `checkEvidenceAgainstManifest`.
 *
 * ── The capture / replay trust boundary, stated explicitly ─────────────────
 *
 * Three genuine EXTERNAL measurements feed this system. They are captured by
 * `scripts/reproducibility-evidence.ts` (an operator tool) and are NOT
 * re-derived here — only replayed byte-for-byte, with their own internal
 * consistency checked as hard as is possible without repeating the
 * measurement:
 *   - LIVE runtime evidence (`liveRuntime`): `eth_getCode` read against a
 *     public RPC, at a SPECIFIC resolved block (not a moving "latest"
 *     label), with the block number/hash and a self-computed
 *     `runtimeCodeHash` recorded. This module does not independently
 *     authenticate Ethereum consensus (no state/account proof is verified)
 *     — it trusts the RPC response, exactly as recorded, and can only prove
 *     internal consistency (e.g. that `runtimeCodeHash` really is
 *     `keccak256(runtimeBytecode)`).
 *   - BUILD evidence (`deploymentCommitBuild`, `publicHeadBuild`): compiled
 *     from a worktree pinned to a specific commit. The capture tool
 *     independently derives the ACTUAL checked-out commit via `git
 *     rev-parse HEAD` (never trusting an operator-supplied label alone),
 *     requires a clean tracked tree, and records per-source-file keccak256
 *     digests (`sourceDigests`) taken directly from solc's own metadata,
 *     cross-checked against the files actually on disk at capture time.
 *
 * What IS independently re-derived, offline, with no network access, by
 * THIS module:
 *   - The solc CBOR metadata boundary (decoded from the bytecode itself, on
 *     BOTH live and local sides — see Blocker D below).
 *   - The normalized executable-code comparison and hash (computed on BOTH
 *     sides, not inferred from one side only).
 *   - Every immutable's expected value, from public inputs.
 *   - The immutable byte-range AUTHORITY itself: which AST ids are even
 *     eligible to claim an exclusion range (see `validateImmutableAuthority`).
 *   - `sourceDigests`, against the actual commit's git objects — see
 *     `verifySourceDigestsAgainstCommit` — WHEN that commit's objects are
 *     locally available (requires a full-history checkout in CI; see
 *     `verifyReportedCommitInPublicHistory`).
 *
 * What this system does NOT protect against: an attacker who edits every
 * cooperating field in a committed evidence/manifest pair simultaneously and
 * consistently, AND who can pass code review. No purely file-based evidence
 * format can prevent that without an external, independently-produced
 * attestation (re-running the compiler, a second independently-operated
 * capture, or a cryptographic chain proof) — none of which this PR adds. The
 * real trust boundary for a fully-coordinated forgery is git history / code
 * review, not this checker. What this module DOES guarantee is that an
 * INCONSISTENT or PARTIAL edit — the common case for an honest mistake, and
 * the case every adversarial test in this module actually exercises — fails
 * loudly and specifically.
 */

import { execFileSync } from "node:child_process";

import { AbiCoder, keccak256, toUtf8Bytes, zeroPadValue } from "ethers";

// ─────────────────────────────────────────────────────────────────────────
// Byte-level helpers
// ─────────────────────────────────────────────────────────────────────────

export function hexToBuffer(hex: string): Buffer {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`Not a well-formed hex string: ${hex.slice(0, 20)}...`);
  }
  return Buffer.from(clean, "hex");
}

export function bufferToHex(buf: Buffer): string {
  return "0x" + buf.toString("hex");
}

// ─────────────────────────────────────────────────────────────────────────
// A minimal CBOR reader — just enough to decode solc's own metadata map
// ({"ipfs"|"bzzr0"|"bzzr1": <bytes>, "solc": <bytes>, ["experimental": true]}),
// so the metadata boundary is PROVEN by decoding, not assumed from a byte
// count. Supports only the major types solc's metadata encoder emits:
// unsigned int (0), byte string (2), text string (3), map (5), simple/bool (7).
// ─────────────────────────────────────────────────────────────────────────

interface CborReadResult {
  value: unknown;
  bytesConsumed: number;
}

function readCborLength(buf: Buffer, offset: number, additionalInfo: number): { length: number; headerBytes: number } {
  if (additionalInfo < 24) return { length: additionalInfo, headerBytes: 0 };
  if (additionalInfo === 24) return { length: buf.readUInt8(offset), headerBytes: 1 };
  if (additionalInfo === 25) return { length: buf.readUInt16BE(offset), headerBytes: 2 };
  if (additionalInfo === 26) return { length: buf.readUInt32BE(offset), headerBytes: 4 };
  throw new Error(`Unsupported CBOR length encoding (additionalInfo=${additionalInfo})`);
}

function readCborItem(buf: Buffer, offset: number): CborReadResult {
  if (offset >= buf.length) throw new Error("CBOR item read past end of buffer");
  const initial = buf.readUInt8(offset);
  const majorType = initial >> 5;
  const additionalInfo = initial & 0x1f;
  let cursor = offset + 1;

  switch (majorType) {
    case 0: {
      // unsigned integer
      const { length, headerBytes } = readCborLength(buf, cursor, additionalInfo);
      cursor += headerBytes;
      return { value: length, bytesConsumed: cursor - offset };
    }
    case 2: {
      // byte string
      const { length, headerBytes } = readCborLength(buf, cursor, additionalInfo);
      cursor += headerBytes;
      if (cursor + length > buf.length) throw new Error("CBOR byte string overruns buffer");
      const value = buf.subarray(cursor, cursor + length);
      cursor += length;
      return { value, bytesConsumed: cursor - offset };
    }
    case 3: {
      // text string
      const { length, headerBytes } = readCborLength(buf, cursor, additionalInfo);
      cursor += headerBytes;
      if (cursor + length > buf.length) throw new Error("CBOR text string overruns buffer");
      const value = buf.subarray(cursor, cursor + length).toString("utf8");
      cursor += length;
      return { value, bytesConsumed: cursor - offset };
    }
    case 5: {
      // map (definite length only — solc never emits indefinite-length maps)
      const { length: entryCount, headerBytes } = readCborLength(buf, cursor, additionalInfo);
      cursor += headerBytes;
      const obj: Record<string, unknown> = {};
      for (let i = 0; i < entryCount; i++) {
        const key = readCborItem(buf, cursor);
        cursor += key.bytesConsumed;
        const val = readCborItem(buf, cursor);
        cursor += val.bytesConsumed;
        obj[String(key.value)] = val.value;
      }
      return { value: obj, bytesConsumed: cursor - offset };
    }
    case 7: {
      // simple values: false(20) true(21) null(22) undefined(23)
      if (additionalInfo === 20) return { value: false, bytesConsumed: 1 };
      if (additionalInfo === 21) return { value: true, bytesConsumed: 1 };
      if (additionalInfo === 22) return { value: null, bytesConsumed: 1 };
      throw new Error(`Unsupported CBOR simple value (additionalInfo=${additionalInfo})`);
    }
    default:
      throw new Error(`Unsupported CBOR major type ${majorType} at offset ${offset}`);
  }
}

export interface MetadataBoundary {
  ok: boolean;
  error?: string;
  /** Byte offset (inclusive) where the CBOR metadata payload begins. */
  cborStart?: number;
  /** Byte offset (exclusive) of the payload end == the 2-byte length prefix start. */
  cborEnd?: number;
  /** Total excluded region, INCLUDING the 2-byte length suffix (`[cborStart, totalLength)`). */
  regionStart?: number;
  regionSize?: number;
  decodedFields?: Record<string, unknown>;
}

/**
 * Decode the trailing solc CBOR build-metadata region from a runtime
 * bytecode buffer, per the Solidity metadata encoding: the LAST 2 bytes are
 * a big-endian length N of the CBOR map immediately preceding them. This
 * PROVES the region boundary by successfully decoding a well-formed CBOR map
 * that consumes exactly N bytes and contains only known solc metadata keys —
 * it does not merely assume a fixed byte count.
 */
export function decodeSolcMetadataBoundary(runtimeHex: string): MetadataBoundary {
  const buf = hexToBuffer(runtimeHex);
  if (buf.length < 2) return { ok: false, error: "runtime bytecode shorter than the 2-byte length suffix" };

  const cborLength = buf.readUInt16BE(buf.length - 2);
  const cborEnd = buf.length - 2;
  const cborStart = cborEnd - cborLength;
  if (cborStart < 0) {
    return { ok: false, error: `declared metadata length (${cborLength}) exceeds available bytecode` };
  }

  let decoded: CborReadResult;
  try {
    decoded = readCborItem(buf, cborStart);
  } catch (err) {
    return { ok: false, error: `CBOR decode failed at offset ${cborStart}: ${(err as Error).message}` };
  }
  if (decoded.bytesConsumed !== cborLength) {
    return {
      ok: false,
      error: `CBOR item consumed ${decoded.bytesConsumed} bytes but the length suffix declared ${cborLength} — not self-consistent`,
    };
  }
  if (typeof decoded.value !== "object" || decoded.value === null || Array.isArray(decoded.value)) {
    return { ok: false, error: "decoded metadata is not a CBOR map" };
  }
  const fields = decoded.value as Record<string, unknown>;
  const KNOWN_KEYS = new Set(["ipfs", "bzzr0", "bzzr1", "solc", "experimental"]);
  const unknownKeys = Object.keys(fields).filter((k) => !KNOWN_KEYS.has(k));
  if (unknownKeys.length > 0) {
    return { ok: false, error: `decoded metadata map has unrecognized key(s): ${unknownKeys.join(", ")}` };
  }
  if (!("solc" in fields)) {
    return { ok: false, error: 'decoded metadata map is missing the required "solc" key' };
  }

  return {
    ok: true,
    cborStart,
    cborEnd,
    regionStart: cborStart,
    regionSize: buf.length - cborStart,
    decodedFields: fields,
  };
}

// ─────────────────────────────────────────────────────────────────────────
// Immutable value derivation — recompute each immutable's EXPECTED bytes
// from public inputs only, so `immutableValuesIndependentlyVerified` is a
// derived fact, never a hand-set boolean.
// ─────────────────────────────────────────────────────────────────────────

const EIP712_DOMAIN_TYPE_HASH = keccak256(
  toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
);

/** OpenZeppelin ShortStrings.toShortString: left-align the UTF-8 bytes in a 32-byte word, OR the byte length into the low byte. */
export function encodeShortString(value: string): string {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > 31) throw new Error(`"${value}" is too long for a ShortString (>31 bytes)`);
  const word = Buffer.alloc(32, 0);
  bytes.copy(word, 0);
  word[31] = bytes.length;
  return bufferToHex(word);
}

export type ImmutableDerivation =
  | { method: "constructor-argument"; value: string }
  | { method: "self-address" }
  | { method: "chain-id" }
  | { method: "keccak256-utf8"; value: string }
  | { method: "short-string"; value: string }
  | { method: "eip712-domain-separator"; name: string; version: string };

export interface ImmutableIdentity {
  astId: string;
  name: string;
  sourceFile: string;
  typeString: string;
  derivation: ImmutableDerivation;
  expectedValueHex: string;
}

export interface DerivationContext {
  deployedAddress: string;
  chainId: number;
}

/** Recompute an immutable's expected 32-byte word from public inputs. Throws on an unknown method. */
export function deriveImmutableExpectedBytes(derivation: ImmutableDerivation, ctx: DerivationContext): string {
  switch (derivation.method) {
    case "constructor-argument":
      return zeroPadValue(derivation.value.toLowerCase(), 32);
    case "self-address":
      return zeroPadValue(ctx.deployedAddress.toLowerCase(), 32);
    case "chain-id":
      return zeroPadValue("0x" + BigInt(ctx.chainId).toString(16), 32);
    case "keccak256-utf8":
      return keccak256(toUtf8Bytes(derivation.value));
    case "short-string":
      return encodeShortString(derivation.value);
    case "eip712-domain-separator": {
      const hashedName = keccak256(toUtf8Bytes(derivation.name));
      const hashedVersion = keccak256(toUtf8Bytes(derivation.version));
      const encoded = AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [EIP712_DOMAIN_TYPE_HASH, hashedName, hashedVersion, ctx.chainId, ctx.deployedAddress],
      );
      return keccak256(encoded);
    }
    default: {
      const exhaustive: never = derivation;
      throw new Error(`Unknown immutable derivation method: ${JSON.stringify(exhaustive)}`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Evidence bundle shape
// ─────────────────────────────────────────────────────────────────────────

export interface CompilerSettings {
  solcLongVersion: string;
  optimizerEnabled: boolean;
  optimizerRuns: number;
  evmVersion: string;
}

/** One immutable VariableDeclaration the compiler's own AST reports as `mutability: "immutable"`, captured mechanically at capture time — NOT hand-typed. The authority checker requires every physically-referenced AST id to appear here. */
export interface ImmutableAstDeclaration {
  astId: string;
  name: string;
  sourceFile: string;
  typeString: string;
}

export interface BuildCapture {
  compiler: CompilerSettings;
  sourceFile: string;
  contractName: string;
  /** solc's own deployedBytecode.object, 0x-prefixed — zero-filled at immutable ranges. */
  deployedBytecodeObject: string;
  /** solc's own deployedBytecode.immutableReferences, keyed by AST node id (string). */
  immutableReferences: Record<string, Array<{ start: number; length: number }>>;
  /** Per-source-file keccak256 of the RAW file bytes, taken from solc's own metadata.sources and cross-checked against the files actually on disk at capture time (see verifySourceDigestsAgainstCommit for the offline half of this proof). */
  sourceDigests: Record<string, string>;
  /** Every immutable VariableDeclaration the compiler's AST reports, across the whole compilation unit — the independent authority for Blocker C. Empty array if the build has no immutables anywhere relevant. */
  immutableAstDeclarations: ImmutableAstDeclaration[];
}

export interface DeploymentCommitBuild extends BuildCapture {
  /** The ACTUAL `git rev-parse HEAD` at capture time — never merely an operator-supplied label (see scripts/reproducibility-evidence.ts capture-build). */
  commit: string;
  sourceTag: string | null;
}

export interface PublicHeadBuild extends BuildCapture {
  /** The ACTUAL `git rev-parse HEAD` at capture time. */
  headCommit: string;
  capturedAt: string;
}

export interface LiveRuntimeCapture {
  address: string;
  chainId: number;
  rpcUrl: string;
  rpcMethod: string;
  /** The EXACT block the code was read at — resolved once via eth_blockNumber, then used for both eth_getBlockByNumber and eth_getCode, never re-resolved as a moving "latest". */
  blockNumber: number;
  blockHash: string;
  capturedAt: string;
  runtimeBytecode: string;
  /** keccak256(runtimeBytecode), computed by the capture tool itself — not trusted from the RPC response. The checker recomputes and cross-checks this too. */
  runtimeCodeHash: string;
}

export interface EvidenceBundle {
  $schema?: string;
  version: "1";
  subject: string;
  liveRuntime: LiveRuntimeCapture;
  deploymentCommitBuild: DeploymentCommitBuild;
  publicHeadBuild: PublicHeadBuild;
  immutableIdentities?: ImmutableIdentity[];
}

// ─────────────────────────────────────────────────────────────────────────
// Blocker A (offline half) — verify sourceDigests against the actual commit's
// git objects, and independently verify reportedSourceCommit is real public
// history. Both require the commit's objects to be locally available (a
// full-history CI checkout); when unavailable, this returns an explicit
// "inconclusive" result rather than silently treating it as failure OR
// success — callers decide how to gate on that (validate-reproducibility.ts
// treats "inconclusive for a reproducible-status manifest" as a hard error:
// never trust the boolean).
// ─────────────────────────────────────────────────────────────────────────

export interface GitAvailability {
  /** True if the commit object itself is present in the local git object database. */
  commitObjectPresent: boolean;
  error?: string;
}

function runGit(args: string[], repoRoot: string): { stdout: Buffer; ok: boolean } {
  try {
    const stdout = execFileSync("git", args, { cwd: repoRoot, stdio: ["ignore", "pipe", "ignore"] });
    return { stdout, ok: true };
  } catch {
    return { stdout: Buffer.alloc(0), ok: false };
  }
}

export function checkCommitObjectAvailable(commit: string, repoRoot: string): GitAvailability {
  const result = runGit(["cat-file", "-e", commit], repoRoot);
  if (!result.ok) {
    return {
      commitObjectPresent: false,
      error: `git object ${commit} is not present locally — this requires a full-history checkout (fetch-depth: 0), not a shallow one`,
    };
  }
  return { commitObjectPresent: true };
}

export interface PublicHistoryVerification {
  /** null means "could not be determined" (commit object unavailable locally) — NEVER coerce this to false. */
  isAncestorOfHead: boolean | null;
  error?: string;
}

/**
 * Independently derive whether `commit` is real, reachable git history —
 * specifically an ancestor of the currently checked-out HEAD — using local
 * git plumbing only. Performs NO network access (no `git fetch`); if the
 * commit's objects are not already present locally, this is inconclusive,
 * not "false".
 */
export function verifyReportedCommitInPublicHistory(commit: string, repoRoot: string): PublicHistoryVerification {
  const availability = checkCommitObjectAvailable(commit, repoRoot);
  if (!availability.commitObjectPresent) {
    return { isAncestorOfHead: null, error: availability.error };
  }
  const result = runGit(["merge-base", "--is-ancestor", commit, "HEAD"], repoRoot);
  return { isAncestorOfHead: result.ok };
}

export interface SourceDigestVerification {
  ok: boolean;
  errors: string[];
  /** null if the commit's objects were unavailable locally — could not be checked either way. */
  checked: boolean;
}

/**
 * Independently verify every (file -> keccak256) pair a build capture
 * recorded actually matches that file's REAL content at the claimed git
 * commit — read directly from git's object database via `git show
 * <commit>:<path>`, not from the operator's own checkout. This is what
 * makes "this build-info corresponds to this commit" a checked fact rather
 * than an operator's unverified label.
 */
export function verifySourceDigestsAgainstCommit(
  commit: string,
  sourceDigests: Record<string, string>,
  repoRoot: string,
): SourceDigestVerification {
  const availability = checkCommitObjectAvailable(commit, repoRoot);
  if (!availability.commitObjectPresent) {
    return { ok: false, errors: [availability.error!], checked: false };
  }
  const errors: string[] = [];
  const entries = Object.entries(sourceDigests);
  if (entries.length === 0) {
    return {
      ok: false,
      errors: ["sourceDigests is empty — a build capture with no bound source files proves nothing"],
      checked: true,
    };
  }
  for (const [file, expectedDigest] of entries) {
    const blob = runGit(["show", `${commit}:${file}`], repoRoot);
    if (!blob.ok) {
      errors.push(`${file}: not found at commit ${commit} (git show failed) — sourceDigests entry cannot be verified`);
      continue;
    }
    const actualDigest = keccak256(blob.stdout);
    if (actualDigest.toLowerCase() !== expectedDigest.toLowerCase()) {
      errors.push(
        `${file}: keccak256 at commit ${commit} is ${actualDigest}, but sourceDigests recorded ${expectedDigest}`,
      );
    }
  }
  return { ok: errors.length === 0, errors, checked: true };
}

// ─────────────────────────────────────────────────────────────────────────
// Blocker C — immutable byte-range AUTHORITY validation. Every AST id that
// claims an exclusion range in immutableReferences must (a) be declared in
// immutableIdentities, one-to-one, and (b) actually appear in the build's
// own immutableAstDeclarations — a machine-derived snapshot of the real AST,
// not a hand-typed label. Ranges themselves must be well-formed, in-bounds,
// non-overlapping, and never enter the decoded metadata region.
// ─────────────────────────────────────────────────────────────────────────

interface ByteRange {
  start: number;
  length: number;
}

function flattenImmutableRanges(
  refs: Record<string, Array<{ start: number; length: number }>>,
): Array<ByteRange & { astId: string }> {
  const out: Array<ByteRange & { astId: string }> = [];
  for (const [astId, ranges] of Object.entries(refs))
    for (const r of ranges) out.push({ astId, start: r.start, length: r.length });
  return out;
}

function inAnyRange(offset: number, ranges: ByteRange[]): boolean {
  return ranges.some((r) => offset >= r.start && offset < r.start + r.length);
}

export interface ImmutableAuthorityCheck {
  ok: boolean;
  errors: string[];
}

export function validateImmutableAuthority(evidence: EvidenceBundle): ImmutableAuthorityCheck {
  const errors: string[] = [];
  const refs = evidence.deploymentCommitBuild.immutableReferences;
  const identities = evidence.immutableIdentities ?? [];
  const astDeclarations = evidence.deploymentCommitBuild.immutableAstDeclarations;

  const declaredIds = identities.map((i) => i.astId);
  const declaredSet = new Set(declaredIds);
  if (declaredSet.size !== declaredIds.length) {
    errors.push("immutableIdentities contains duplicate astId entries");
  }
  const referencedSet = new Set(Object.keys(refs));
  const astDeclaredSet = new Set(astDeclarations.map((d) => d.astId));

  for (const id of referencedSet) {
    if (!declaredSet.has(id)) {
      errors.push(
        `immutableReferences declares AST id ${id} with no corresponding immutableIdentities entry — an undeclared exclusion range has no authority`,
      );
    }
    if (!astDeclaredSet.has(id)) {
      errors.push(
        `immutableReferences declares AST id ${id}, but no VariableDeclaration with that id and mutability "immutable" was found anywhere in deploymentCommitBuild.immutableAstDeclarations (the build's own AST) — this exclusion range does not correspond to anything the compiler actually emitted as immutable`,
      );
    }
  }
  for (const id of declaredSet) {
    if (!referencedSet.has(id)) {
      errors.push(
        `immutableIdentities declares AST id ${id}, but deploymentCommitBuild.immutableReferences has no range for it`,
      );
    }
  }
  if (declaredSet.size === 0 && referencedSet.size > 0) {
    errors.push("no immutableIdentities declared, but deploymentCommitBuild.immutableReferences is non-empty");
  }

  const localLen = hexToBuffer(evidence.deploymentCommitBuild.deployedBytecodeObject).length;
  const localBoundary = decodeSolcMetadataBoundary(evidence.deploymentCommitBuild.deployedBytecodeObject);

  const allRanges = flattenImmutableRanges(refs);
  for (const r of allRanges) {
    if (!Number.isInteger(r.start) || r.start < 0) {
      errors.push(`immutableReferences[${r.astId}]: start must be a non-negative integer (got ${r.start})`);
    }
    if (!Number.isInteger(r.length) || r.length < 1 || r.length > 32) {
      errors.push(`immutableReferences[${r.astId}]: length must be an integer in [1, 32] (got ${r.length})`);
    }
    if (r.start + r.length > localLen) {
      errors.push(
        `immutableReferences[${r.astId}]: range [${r.start}, ${r.start + r.length}) exceeds bytecode length ${localLen}`,
      );
    }
    if (localBoundary.ok && r.start + r.length > localBoundary.regionStart!) {
      errors.push(
        `immutableReferences[${r.astId}]: range [${r.start}, ${r.start + r.length}) enters the decoded metadata region (starts at ${localBoundary.regionStart}) — an immutable cannot legitimately overlap compiler metadata`,
      );
    }
  }
  for (const [astId, ranges] of Object.entries(refs)) {
    if (ranges.length === 0) errors.push(`immutableReferences[${astId}]: has zero physical references`);
  }
  const sorted = [...allRanges].sort((a, b) => a.start - b.start);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    if (cur.start < prev.start + prev.length) {
      errors.push(
        `immutable ranges overlap: ${prev.astId}[${prev.start}, ${prev.start + prev.length}) and ${cur.astId}[${cur.start}, ${cur.start + cur.length})`,
      );
    }
  }

  return { ok: errors.length === 0, errors };
}

// ─────────────────────────────────────────────────────────────────────────
// The checker
// ─────────────────────────────────────────────────────────────────────────

function maskRanges(buf: Buffer, ranges: ByteRange[]): Buffer {
  const masked = Buffer.from(buf);
  for (const r of ranges) masked.fill(0, r.start, r.start + r.length);
  return masked;
}

export interface DerivedFacts {
  observedRuntimeBytes: number;
  reportedCommitRuntimeBytes: number;
  publicHeadRuntimeBytes: number;
  liveMetadataBoundary: MetadataBoundary;
  localMetadataBoundary: MetadataBoundary;
  /** Blocker D: metadata exclusion is only authorized when BOTH sides decode to the SAME region — never inferred from the live side alone. */
  metadataBoundariesAgree: boolean;
  /** Every byte offset where raw live bytes differ from raw local (deployment-commit-build) bytes. */
  rawDiffOffsets: number[];
  /** Of those, the ones that fall inside the decoded (dual-authorized) metadata region. */
  metadataTrailerBytesExcluded: number;
  /** True only if EVERY raw diff offset is inside an AUTHORIZED immutable range or inside a dual-authorized metadata region, AND the full normalized buffers are byte-equal on both sides. */
  executableBytecodeMatch: boolean;
  metadataHashMatch: boolean;
  /** Blocker D: hashed independently on both sides; only meaningful (and only reported equal) when they actually match. */
  normalizedLiveHash: string;
  normalizedLocalHash: string;
  normalizedBytecodeHash: string;
  immutableAuthority: ImmutableAuthorityCheck;
  immutableResults: Array<{
    astId: string;
    name: string;
    expectedValueHex: string;
    observedValueHex: string | null;
    physicalOccurrencesAgree: boolean;
    match: boolean;
  }>;
  immutableValuesIndependentlyVerified: boolean | null;
}

export function deriveFactsFromEvidence(evidence: EvidenceBundle): DerivedFacts {
  const live = hexToBuffer(evidence.liveRuntime.runtimeBytecode);
  const local = hexToBuffer(evidence.deploymentCommitBuild.deployedBytecodeObject);
  const head = hexToBuffer(evidence.publicHeadBuild.deployedBytecodeObject);

  const liveMetadataBoundary = decodeSolcMetadataBoundary(evidence.liveRuntime.runtimeBytecode);
  const localMetadataBoundary = decodeSolcMetadataBoundary(evidence.deploymentCommitBuild.deployedBytecodeObject);
  const metadataBoundariesAgree =
    liveMetadataBoundary.ok &&
    localMetadataBoundary.ok &&
    liveMetadataBoundary.regionStart === localMetadataBoundary.regionStart &&
    liveMetadataBoundary.regionSize === localMetadataBoundary.regionSize;

  const immutableAuthority = validateImmutableAuthority(evidence);
  // Only ranges that pass the authority check are trusted as exclusion zones.
  // An unauthorized "extra" range therefore buys the forger nothing: bytes
  // under it are still treated as executable code for comparison purposes.
  const authorizedAstIds = immutableAuthority.ok
    ? new Set(Object.keys(evidence.deploymentCommitBuild.immutableReferences))
    : new Set((evidence.immutableIdentities ?? []).map((i) => i.astId));
  const rawRefs = evidence.deploymentCommitBuild.immutableReferences;
  const authorizedRanges = flattenImmutableRanges(
    Object.fromEntries(Object.entries(rawRefs).filter(([id]) => authorizedAstIds.has(id))),
  );

  const rawDiffOffsets: number[] = [];
  if (live.length === local.length) {
    for (let i = 0; i < live.length; i++) if (live[i] !== local[i]) rawDiffOffsets.push(i);
  }

  // Metadata exclusion requires DUAL authorization: both sides must decode a
  // well-formed metadata region, AND that region must be at the identical
  // offset/size on both sides. A boundary mismatch (e.g. a shifted region)
  // grants NO exclusion at all — every byte is then classified as executable.
  const metadataRegionStart = metadataBoundariesAgree ? liveMetadataBoundary.regionStart! : Infinity;

  let metadataTrailerBytesExcluded = 0;
  let allDiffsAccountedFor = live.length === local.length;
  for (const offset of rawDiffOffsets) {
    const insideImmutable = inAnyRange(offset, authorizedRanges);
    const insideMetadata = offset >= metadataRegionStart;
    if (insideMetadata && !insideImmutable) metadataTrailerBytesExcluded++;
    if (!insideImmutable && !insideMetadata) allDiffsAccountedFor = false;
  }

  const maskRangesFor = (
    boundaryOk: boolean,
    regionStart: number | undefined,
    regionSize: number | undefined,
  ): ByteRange[] => {
    const ranges: ByteRange[] = [...authorizedRanges];
    if (metadataBoundariesAgree && boundaryOk && regionStart !== undefined && regionSize !== undefined) {
      ranges.push({ start: regionStart, length: regionSize });
    }
    return ranges;
  };
  const liveMasked =
    live.length === local.length
      ? maskRanges(
          live,
          maskRangesFor(liveMetadataBoundary.ok, liveMetadataBoundary.regionStart, liveMetadataBoundary.regionSize),
        )
      : live;
  const localMasked = maskRanges(
    local,
    maskRangesFor(localMetadataBoundary.ok, localMetadataBoundary.regionStart, localMetadataBoundary.regionSize),
  );
  const normalizedLiveHash = keccak256(bufferToHex(liveMasked));
  const normalizedLocalHash = keccak256(bufferToHex(localMasked));
  // Blocker D: don't infer equality from a single hash — compare the actual
  // normalized buffers, and require the independently-computed hashes agree.
  const normalizedBuffersEqual = live.length === local.length && liveMasked.equals(localMasked);
  const executableBytecodeMatch =
    immutableAuthority.ok &&
    allDiffsAccountedFor &&
    normalizedBuffersEqual &&
    normalizedLiveHash === normalizedLocalHash;
  const normalizedBytecodeHash = normalizedLocalHash;

  const metadataHashMatch =
    metadataBoundariesAgree &&
    live.length === local.length &&
    live.subarray(liveMetadataBoundary.regionStart!).equals(local.subarray(localMetadataBoundary.regionStart!));

  const context: DerivationContext = {
    deployedAddress: evidence.liveRuntime.address,
    chainId: evidence.liveRuntime.chainId,
  };
  const immutableResults = (evidence.immutableIdentities ?? []).map((identity) => {
    const refs = evidence.deploymentCommitBuild.immutableReferences[identity.astId];
    if (!refs || refs.length === 0) {
      return {
        astId: identity.astId,
        name: identity.name,
        expectedValueHex: identity.expectedValueHex,
        observedValueHex: null,
        physicalOccurrencesAgree: false,
        match: false,
      };
    }
    const observedValues = refs.map((r) => bufferToHex(live.subarray(r.start, r.start + r.length)));
    const physicalOccurrencesAgree = observedValues.every((v) => v.toLowerCase() === observedValues[0].toLowerCase());
    const observedValueHex = physicalOccurrencesAgree ? observedValues[0] : null;
    const derivedExpected = deriveImmutableExpectedBytes(identity.derivation, context);
    const expectedMatchesPinned = derivedExpected.toLowerCase() === identity.expectedValueHex.toLowerCase();
    const match =
      physicalOccurrencesAgree &&
      expectedMatchesPinned &&
      observedValueHex !== null &&
      observedValueHex.toLowerCase() === derivedExpected.toLowerCase();
    return {
      astId: identity.astId,
      name: identity.name,
      expectedValueHex: derivedExpected,
      observedValueHex,
      physicalOccurrencesAgree,
      match,
    };
  });

  const immutableValuesIndependentlyVerified =
    evidence.immutableIdentities === undefined || evidence.immutableIdentities.length === 0
      ? null
      : immutableAuthority.ok && immutableResults.every((r) => r.match);

  return {
    observedRuntimeBytes: live.length,
    reportedCommitRuntimeBytes: local.length,
    publicHeadRuntimeBytes: head.length,
    liveMetadataBoundary,
    localMetadataBoundary,
    metadataBoundariesAgree,
    rawDiffOffsets,
    metadataTrailerBytesExcluded,
    executableBytecodeMatch,
    metadataHashMatch,
    normalizedLiveHash,
    normalizedLocalHash,
    normalizedBytecodeHash,
    immutableAuthority,
    immutableResults,
    immutableValuesIndependentlyVerified,
  };
}

export interface EvidenceCheckResult {
  ok: boolean;
  errors: string[];
  facts: DerivedFacts;
}

/**
 * The core assurance boundary: recompute every fact from the evidence bundle
 * and require the manifest's own recorded claims to agree with the
 * recomputation. A manifest field is never accepted on its own say-so.
 *
 * `repoRoot`, when supplied, additionally verifies (a) the deployment
 * commit's sourceDigests against its ACTUAL git objects and (b) that the
 * commit is real, reachable history — both requiring the commit's objects to
 * be locally available (a full-history checkout). When `repoRoot` is
 * omitted, those two checks are skipped explicitly (not silently passed) —
 * callers that need the strongest guarantee must supply it.
 */
export function checkEvidenceAgainstManifest(
  evidence: EvidenceBundle,
  manifest: Record<string, unknown>,
  repoRoot?: string,
): EvidenceCheckResult {
  const errors: string[] = [];

  // ── IDENTITY CROSS-CHECK ────────────────────────────────────────────────
  // The evidence bundle must actually BE evidence for this manifest, not just
  // syntactically valid evidence for something else.
  if (evidence.subject !== manifest["subject"]) {
    errors.push(`evidence.subject (${evidence.subject}) does not match manifest.subject (${manifest["subject"]})`);
  }
  if (evidence.liveRuntime.address.toLowerCase() !== String(manifest["deployedAddress"]).toLowerCase()) {
    errors.push(
      `evidence.liveRuntime.address (${evidence.liveRuntime.address}) does not match manifest.deployedAddress (${manifest["deployedAddress"]})`,
    );
  }
  if (evidence.liveRuntime.chainId !== manifest["chainId"]) {
    errors.push(
      `evidence.liveRuntime.chainId (${evidence.liveRuntime.chainId}) does not match manifest.chainId (${manifest["chainId"]})`,
    );
  }
  if (evidence.deploymentCommitBuild.commit !== manifest["reportedSourceCommit"]) {
    errors.push(
      `evidence.deploymentCommitBuild.commit (${evidence.deploymentCommitBuild.commit}) does not match manifest.reportedSourceCommit (${manifest["reportedSourceCommit"]})`,
    );
  }
  if (manifest["publicHeadCommit"] != null && evidence.publicHeadBuild.headCommit !== manifest["publicHeadCommit"]) {
    errors.push(
      `evidence.publicHeadBuild.headCommit (${evidence.publicHeadBuild.headCommit}) does not match manifest.publicHeadCommit (${manifest["publicHeadCommit"]}) — a stale or substituted public-HEAD capture cannot be silently relabeled as current`,
    );
  }

  // ── Blocker A (offline half) ────────────────────────────────────────────
  if (repoRoot) {
    const history = verifyReportedCommitInPublicHistory(evidence.deploymentCommitBuild.commit, repoRoot);
    if (history.isAncestorOfHead === null) {
      errors.push(`reportedSourceCommit public-history check inconclusive: ${history.error}`);
    } else if (history.isAncestorOfHead !== manifest["reportedSourceCommitInPublicHistory"]) {
      errors.push(
        `reportedSourceCommitInPublicHistory: manifest says ${manifest["reportedSourceCommitInPublicHistory"]}, independently derived (git merge-base --is-ancestor) value is ${history.isAncestorOfHead}`,
      );
    }
    const digestCheck = verifySourceDigestsAgainstCommit(
      evidence.deploymentCommitBuild.commit,
      evidence.deploymentCommitBuild.sourceDigests,
      repoRoot,
    );
    if (!digestCheck.ok) {
      for (const e of digestCheck.errors) errors.push(`[source-commit binding] ${e}`);
    }
    // The SAME binding proof applies to the public-HEAD capture: a stale or substituted
    // headCommit label cannot be trusted just because it matches the manifest's own
    // publicHeadCommit — both could be consistently wrong. Independently verifying
    // sourceDigests against that commit's real git objects closes that common-mode gap.
    const headDigestCheck = verifySourceDigestsAgainstCommit(
      evidence.publicHeadBuild.headCommit,
      evidence.publicHeadBuild.sourceDigests,
      repoRoot,
    );
    if (!headDigestCheck.ok) {
      for (const e of headDigestCheck.errors) errors.push(`[public-head binding] ${e}`);
    }
  }

  // ── Blocker C: derived identities must reference a constructor argument that is
  // actually part of the recorded, public deployment — not an invented value. ────
  const am = manifest["artifactManifest"] as Record<string, unknown> | null | undefined;
  const recordedConstructorArgs = new Set(
    (Array.isArray(am?.["constructorArgs"]) ? (am!["constructorArgs"] as unknown[]) : []).map((v) =>
      String(v).toLowerCase(),
    ),
  );
  for (const identity of evidence.immutableIdentities ?? []) {
    if (identity.derivation.method === "constructor-argument") {
      if (!recordedConstructorArgs.has(identity.derivation.value.toLowerCase())) {
        errors.push(
          `immutable "${identity.name}" (AST id ${identity.astId}) derives from constructor-argument "${identity.derivation.value}", which is not present in artifactManifest.constructorArgs — a constructor-argument derivation must reference an actually-recorded, public deployment argument`,
        );
      }
    }
  }

  const facts = deriveFactsFromEvidence(evidence);

  if (!facts.immutableAuthority.ok) {
    for (const e of facts.immutableAuthority.errors) errors.push(`[immutable authority] ${e}`);
  }

  if (!facts.liveMetadataBoundary.ok) {
    errors.push(`live runtime bytecode: metadata boundary did not decode: ${facts.liveMetadataBoundary.error}`);
  }
  if (!facts.localMetadataBoundary.ok) {
    errors.push(`deployment-commit build: metadata boundary did not decode: ${facts.localMetadataBoundary.error}`);
  }
  if (facts.liveMetadataBoundary.ok && facts.localMetadataBoundary.ok && !facts.metadataBoundariesAgree) {
    errors.push(
      `metadata boundaries disagree between live and deployment-commit build (live: [${facts.liveMetadataBoundary.regionStart}, +${facts.liveMetadataBoundary.regionSize}), local: [${facts.localMetadataBoundary.regionStart}, +${facts.localMetadataBoundary.regionSize})) — no metadata exclusion is authorized`,
    );
  }

  const observed = manifest["observedRuntimeBytes"];
  if (observed !== facts.observedRuntimeBytes) {
    errors.push(
      `observedRuntimeBytes: manifest says ${observed}, evidence (live capture) says ${facts.observedRuntimeBytes}`,
    );
  }
  const publicHead = manifest["publicHeadRuntimeBytes"];
  if (publicHead !== facts.publicHeadRuntimeBytes) {
    errors.push(
      `publicHeadRuntimeBytes: manifest says ${publicHead}, evidence (public-HEAD build) says ${facts.publicHeadRuntimeBytes}`,
    );
  }
  const reportedCommit = manifest["reportedCommitRuntimeBytes"];
  if (reportedCommit !== facts.reportedCommitRuntimeBytes) {
    errors.push(
      `reportedCommitRuntimeBytes: manifest says ${reportedCommit}, evidence (deployment-commit build) says ${facts.reportedCommitRuntimeBytes}`,
    );
  }

  if (am && typeof am === "object") {
    if (am["executableBytecodeMatch"] !== facts.executableBytecodeMatch) {
      errors.push(
        `artifactManifest.executableBytecodeMatch: manifest says ${am["executableBytecodeMatch"]}, evidence-derived value is ${facts.executableBytecodeMatch}`,
      );
    }
    if (am["metadataHashMatch"] !== facts.metadataHashMatch) {
      errors.push(
        `artifactManifest.metadataHashMatch: manifest says ${am["metadataHashMatch"]}, evidence-derived value is ${facts.metadataHashMatch}`,
      );
    }
    if (facts.metadataHashMatch === false) {
      if (am["metadataTrailerBytesExcluded"] !== facts.metadataTrailerBytesExcluded) {
        errors.push(
          `artifactManifest.metadataTrailerBytesExcluded: manifest says ${am["metadataTrailerBytesExcluded"]}, evidence-derived value is ${facts.metadataTrailerBytesExcluded}`,
        );
      }
      // The core containment invariant: every excluded byte must lie inside the
      // DUAL-AUTHORIZED decoded metadata region or an AUTHORIZED immutable range,
      // never merely under an arbitrary count ceiling.
      if (facts.metadataBoundariesAgree) {
        const region = facts.liveMetadataBoundary;
        const authorizedRanges = facts.immutableAuthority.ok
          ? flattenImmutableRanges(evidence.deploymentCommitBuild.immutableReferences)
          : [];
        const outside = facts.rawDiffOffsets.filter(
          (o) =>
            !(o >= region.regionStart! && o < region.regionStart! + region.regionSize!) &&
            !inAnyRange(o, authorizedRanges),
        );
        if (outside.length > 0) {
          errors.push(
            `excludedRange is NOT contained in the decoded solc metadata region: byte offset(s) ${outside.slice(0, 5).join(", ")} differ outside both the metadata region [${region.regionStart}, ${region.regionStart! + region.regionSize!}) and every AUTHORIZED immutable range — this is a real code divergence, not excludable metadata`,
          );
        }
      }
    }
    if (am["bytecodeHash"] !== facts.normalizedBytecodeHash) {
      errors.push(
        `artifactManifest.bytecodeHash: manifest says ${am["bytecodeHash"]}, evidence-derived normalized hash is ${facts.normalizedBytecodeHash}`,
      );
    }
    if (facts.immutableValuesIndependentlyVerified !== null) {
      if (am["immutableValuesIndependentlyVerified"] !== facts.immutableValuesIndependentlyVerified) {
        errors.push(
          `artifactManifest.immutableValuesIndependentlyVerified: manifest says ${am["immutableValuesIndependentlyVerified"]}, evidence-derived value is ${facts.immutableValuesIndependentlyVerified}`,
        );
      }
      for (const r of facts.immutableResults) {
        if (!r.match) {
          errors.push(
            `immutable "${r.name}" (AST id ${r.astId}): expected ${r.expectedValueHex}, observed ${r.observedValueHex ?? "(physical occurrences disagree)"}`,
          );
        }
      }
    }
  } else if (manifest["reproducibilityStatus"] === "reproducible") {
    errors.push("reproducibilityStatus is 'reproducible' but artifactManifest is missing/null");
  }

  return { ok: errors.length === 0, errors, facts };
}
