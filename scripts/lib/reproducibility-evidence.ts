/**
 * Deterministic, offline replay of a deployment-reproducibility claim from a
 * committed evidence bundle.
 *
 * A reproducibility manifest (deployments/reproducibility/*.json) previously
 * carried hand-set booleans (`executableBytecodeMatch`,
 * `immutableValuesIndependentlyVerified`, `bytecodeHash`, ...) that the
 * validator only format-checked — nothing re-derived them. This module makes
 * those facts REPLAYABLE: given a committed evidence bundle (raw captured
 * bytecode + solc's own `immutableReferences` + the public inputs needed to
 * re-derive each immutable value), every one of those facts is recomputed
 * from scratch, and the manifest's own claims are cross-checked against the
 * recomputation. No field in the manifest is ever trusted as its own
 * authority; see `checkEvidenceAgainstManifest`.
 *
 * Two kinds of measurement feed this:
 *   - LIVE runtime evidence (`liveRuntime`): captured by reading `eth_getCode`
 *     against a public RPC. This is a genuine external measurement — network-
 *     dependent, captured with provenance (RPC URL, block tag, timestamp) —
 *     and is NOT re-derived here, only replayed byte-for-byte from the
 *     committed capture.
 *   - BUILD evidence (`deploymentCommitBuild`, `publicHeadBuild`): captured by
 *     compiling the pinned commit / current public HEAD with that commit's
 *     own lockfile/toolchain, in an isolated worktree. Also a genuine
 *     external measurement (solc is deterministic given identical inputs,
 *     but the capture itself — checking out a specific commit and installing
 *     its exact dependencies — is an operator action, not something this
 *     module performs).
 *
 * Everything downstream of those two captures — the metadata boundary, the
 * normalized comparison, the normalized hash, and every immutable
 * expected/observed comparison — is derived HERE, deterministically, with no
 * network access.
 */

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

export interface BuildCapture {
  compiler: CompilerSettings;
  sourceFile: string;
  contractName: string;
  /** solc's own deployedBytecode.object, 0x-prefixed — zero-filled at immutable ranges. */
  deployedBytecodeObject: string;
  /** solc's own deployedBytecode.immutableReferences, keyed by AST node id (string). */
  immutableReferences: Record<string, Array<{ start: number; length: number }>>;
}

export interface DeploymentCommitBuild extends BuildCapture {
  commit: string;
  sourceTag: string | null;
}

export interface PublicHeadBuild extends BuildCapture {
  headCommit: string;
  capturedAt: string;
}

export interface LiveRuntimeCapture {
  address: string;
  chainId: number;
  rpcUrl: string;
  rpcMethod: string;
  blockTag: string;
  capturedAt: string;
  runtimeBytecode: string;
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
// The checker
// ─────────────────────────────────────────────────────────────────────────

interface ByteRange {
  start: number;
  length: number;
}

function flattenImmutableRanges(refs: Record<string, Array<{ start: number; length: number }>>): ByteRange[] {
  const out: ByteRange[] = [];
  for (const ranges of Object.values(refs)) for (const r of ranges) out.push({ start: r.start, length: r.length });
  return out;
}

function maskRanges(buf: Buffer, ranges: ByteRange[]): Buffer {
  const masked = Buffer.from(buf);
  for (const r of ranges) masked.fill(0, r.start, r.start + r.length);
  return masked;
}

function inAnyRange(offset: number, ranges: ByteRange[]): boolean {
  return ranges.some((r) => offset >= r.start && offset < r.start + r.length);
}

export interface DerivedFacts {
  observedRuntimeBytes: number;
  reportedCommitRuntimeBytes: number;
  publicHeadRuntimeBytes: number;
  liveMetadataBoundary: MetadataBoundary;
  localMetadataBoundary: MetadataBoundary;
  /** Every byte offset where raw live bytes differ from raw local (deployment-commit-build) bytes. */
  rawDiffOffsets: number[];
  /** Of those, the ones that fall inside the decoded live metadata region. */
  metadataTrailerBytesExcluded: number;
  /** True only if EVERY raw diff offset is inside an immutable range or inside the metadata region. */
  executableBytecodeMatch: boolean;
  metadataHashMatch: boolean;
  normalizedBytecodeHash: string;
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

  const immutableRanges = flattenImmutableRanges(evidence.deploymentCommitBuild.immutableReferences);

  const rawDiffOffsets: number[] = [];
  if (live.length === local.length) {
    for (let i = 0; i < live.length; i++) if (live[i] !== local[i]) rawDiffOffsets.push(i);
  }

  const metadataRegionStart = liveMetadataBoundary.ok ? liveMetadataBoundary.regionStart! : Infinity;
  let metadataTrailerBytesExcluded = 0;
  let executableBytecodeMatch = live.length === local.length && liveMetadataBoundary.ok && localMetadataBoundary.ok;
  for (const offset of rawDiffOffsets) {
    const insideImmutable = inAnyRange(offset, immutableRanges);
    const insideMetadata = offset >= metadataRegionStart;
    if (insideMetadata && !insideImmutable) metadataTrailerBytesExcluded++;
    if (!insideImmutable && !insideMetadata) executableBytecodeMatch = false;
  }

  const liveMasked =
    live.length === local.length
      ? maskRanges(maskRanges(live, immutableRanges), rangeFromBoundary(liveMetadataBoundary))
      : live;
  const localMasked = maskRanges(maskRanges(local, immutableRanges), rangeFromBoundary(localMetadataBoundary));
  const normalizedBytecodeHash = keccak256(bufferToHex(localMasked));

  const metadataHashMatch =
    liveMetadataBoundary.ok &&
    localMetadataBoundary.ok &&
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
      : immutableResults.every((r) => r.match);

  return {
    observedRuntimeBytes: live.length,
    reportedCommitRuntimeBytes: local.length,
    publicHeadRuntimeBytes: head.length,
    liveMetadataBoundary,
    localMetadataBoundary,
    rawDiffOffsets,
    metadataTrailerBytesExcluded,
    executableBytecodeMatch,
    metadataHashMatch,
    normalizedBytecodeHash,
    immutableResults,
    immutableValuesIndependentlyVerified,
  };
}

function rangeFromBoundary(b: MetadataBoundary): ByteRange[] {
  if (!b.ok || b.regionStart === undefined || b.regionSize === undefined) return [];
  return [{ start: b.regionStart, length: b.regionSize }];
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
 */
export function checkEvidenceAgainstManifest(
  evidence: EvidenceBundle,
  manifest: Record<string, unknown>,
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

  const facts = deriveFactsFromEvidence(evidence);

  if (!facts.liveMetadataBoundary.ok) {
    errors.push(`live runtime bytecode: metadata boundary did not decode: ${facts.liveMetadataBoundary.error}`);
  }
  if (!facts.localMetadataBoundary.ok) {
    errors.push(`deployment-commit build: metadata boundary did not decode: ${facts.localMetadataBoundary.error}`);
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

  const am = manifest["artifactManifest"] as Record<string, unknown> | null | undefined;
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
      // DECODED metadata region, never merely under an arbitrary count ceiling.
      if (facts.liveMetadataBoundary.ok) {
        const region = facts.liveMetadataBoundary;
        const outside = facts.rawDiffOffsets.filter(
          (o) =>
            !(o >= region.regionStart! && o < region.regionStart! + region.regionSize!) &&
            !inAnyRangeExport(o, evidence),
        );
        if (outside.length > 0) {
          errors.push(
            `excludedRange is NOT contained in the decoded solc metadata region: byte offset(s) ${outside.slice(0, 5).join(", ")} differ outside both the metadata region [${region.regionStart}, ${region.regionStart! + region.regionSize!}) and every declared immutable range — this is a real code divergence, not excludable metadata`,
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

function inAnyRangeExport(offset: number, evidence: EvidenceBundle): boolean {
  return inAnyRange(offset, flattenImmutableRanges(evidence.deploymentCommitBuild.immutableReferences));
}
