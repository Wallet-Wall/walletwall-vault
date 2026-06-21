import { readFileSync } from "node:fs";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import type { BytesLike, Signer, TypedDataDomain } from "ethers";
import { AbiCoder, getAddress, getBytes, hexlify, isHexString, keccak256, toUtf8Bytes } from "ethers";

// Core ML-DSA-65 verification now lives in the open, independently hostable
// verifier boundary. This module only consumes its result; it never duplicates
// the verification logic. See src/verifier/ and docs/Open_PQ_Verifier.md.
export type { PQVerificationResult } from "../../src/verifier/ml-dsa-65";
// @ts-expect-error ts-node ESM requires the explicit extension.
import { verifyMLDSA65 as verifyMLDSA65Pure, verifyMLDSA65Detailed } from "../../src/verifier/ml-dsa-65.ts";

export { verifyMLDSA65Detailed };

export const ATTESTATION_ALGORITHM_ID = keccak256(toUtf8Bytes("ATTESTED-ML-DSA-65"));
export const ATTESTATION_DOMAIN_NAME = "AttestationPQCVerifier";
export const ATTESTATION_DOMAIN_VERSION = "1";
export const DEMO_WARNING = "DEMO ONLY — do not use generated/demo PQ material for real funds.";
export const DEMO_SEED = getBytes("0x" + "42".repeat(32));
export const DEMO_WITHDRAWAL_DIGEST = keccak256(toUtf8Bytes("WalletWall ML-DSA attestor demo"));
export const FIXTURE_SEED = getBytes("0x" + "43".repeat(32));
export const FIXTURE_WITHDRAWAL_DIGEST = keccak256(toUtf8Bytes("WalletWall ML-DSA attestor fixture"));

export const ATTESTATION_TYPES = {
  PQCAttestation: [
    { name: "withdrawalDigest", type: "bytes32" },
    { name: "publicKeyHash", type: "bytes32" },
    { name: "pqSignatureHash", type: "bytes32" },
    { name: "algorithmId", type: "bytes32" },
    { name: "verifier", type: "address" },
    { name: "chainId", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

export interface AttestationInput {
  withdrawalDigest: string;
  publicKey: Uint8Array;
  pqSignature: Uint8Array;
  signedMessage: Uint8Array;
  verifierAddress: string;
  chainId: bigint;
  deadline: bigint;
}

export interface SignedAttestation {
  attestationSignature: string;
  publicKeyHash: string;
  pqSignatureHash: string;
  verifierPayload: string;
}

export interface ParsedAttestorArgs {
  mode: "demo" | "verify";
  values: Map<string, string>;
}

export function parseAttestorArgs(args: string[]): ParsedAttestorArgs {
  const mode = args[0] ?? "demo";
  if (mode !== "demo" && mode !== "verify") throw new Error("Mode must be demo or verify");

  const values = new Map<string, string>();
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i];
    const value = args[i + 1];
    if (!flag?.startsWith("--") || value === undefined) {
      throw new Error(`Malformed argument near ${flag ?? "<end>"}`);
    }
    values.set(flag.slice(2), value);
  }
  return { mode, values };
}

export function normalizeHex(value: string, name: string, expectedLength?: number): Uint8Array {
  if (!isHexString(value)) throw new Error(`${name} must be a 0x-prefixed even-length hex string`);

  const bytes = getBytes(value);
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new Error(`${name} must be exactly ${expectedLength} bytes`);
  }
  return bytes;
}

export function readBytesInput(value: string | undefined, filePath: string | undefined, name: string): Uint8Array {
  if ((value === undefined) === (filePath === undefined)) {
    throw new Error(`Provide exactly one of --${name} or --${name}-file`);
  }
  if (value !== undefined) return normalizeHex(value, name);

  const file = readFileSync(filePath!);
  const text = file.toString("utf8").trim();
  return text.startsWith("0x") ? normalizeHex(text, name) : new Uint8Array(file);
}

export function normalizeWithdrawalDigest(value: string | undefined): string {
  if (value === undefined) throw new Error("Missing required --withdrawal-digest");
  return hexlify(normalizeHex(value, "withdrawal-digest", 32));
}

export function hashPQPublicKey(publicKey: BytesLike): string {
  return keccak256(publicKey);
}

export function hashPQSignature(signature: BytesLike): string {
  return keccak256(signature);
}

/**
 * Backwards-compatible boolean wrapper. Delegates to the open verifier module so
 * that this file no longer owns the core ML-DSA-65 verification logic. Existing
 * importers (CLI, conformance tests) keep the same signature and behavior.
 */
export function verifyMLDSA65(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return verifyMLDSA65Pure(publicKey, message, signature);
}

export function createDemoMaterial() {
  const keyPair = ml_dsa65.keygen(DEMO_SEED);
  const message = getBytes(DEMO_WITHDRAWAL_DIGEST);
  const signature = ml_dsa65.sign(message, keyPair.secretKey, { extraEntropy: false });
  return { publicKey: keyPair.publicKey, signature, message };
}

export function createFixtureMaterial() {
  const keyPair = ml_dsa65.keygen(FIXTURE_SEED);
  const message = getBytes(FIXTURE_WITHDRAWAL_DIGEST);
  const signature = ml_dsa65.sign(message, keyPair.secretKey, { extraEntropy: false });
  return { publicKey: keyPair.publicKey, signature, message };
}

export function isDemoMaterial(publicKey: Uint8Array, signature: Uint8Array): boolean {
  const demo = createDemoMaterial();
  return (
    hashPQPublicKey(publicKey) === hashPQPublicKey(demo.publicKey) ||
    hashPQSignature(signature) === hashPQSignature(demo.signature)
  );
}

export function isFixtureMaterial(publicKey: Uint8Array, signature: Uint8Array): boolean {
  const fixture = createFixtureMaterial();
  return (
    hashPQPublicKey(publicKey) === hashPQPublicKey(fixture.publicKey) ||
    hashPQSignature(signature) === hashPQSignature(fixture.signature)
  );
}

export function buildAttestation(input: AttestationInput, publicKeyHash: string, pqSignatureHash: string) {
  const verifier = getAddress(input.verifierAddress);
  const domain: TypedDataDomain = {
    name: ATTESTATION_DOMAIN_NAME,
    version: ATTESTATION_DOMAIN_VERSION,
    chainId: input.chainId,
    verifyingContract: verifier,
  };
  const value = {
    withdrawalDigest: input.withdrawalDigest,
    publicKeyHash,
    pqSignatureHash,
    algorithmId: ATTESTATION_ALGORITHM_ID,
    verifier,
    chainId: input.chainId,
    deadline: input.deadline,
  };
  return { domain, value };
}

export function encodeVerifierPayload(
  attestationSignature: string,
  deadline: bigint,
  publicKeyHash: string,
  pqSignatureHash: string,
): string {
  return AbiCoder.defaultAbiCoder().encode(
    ["bytes", "uint256", "bytes32", "bytes32"],
    [attestationSignature, deadline, publicKeyHash, pqSignatureHash],
  );
}

export async function verifyAndSignAttestation(
  input: AttestationInput,
  attestor: Signer,
  allowGeneratedMaterial = false,
): Promise<SignedAttestation> {
  const digestBytes = normalizeHex(input.withdrawalDigest, "withdrawal-digest", 32);
  if (hexlify(input.signedMessage) !== hexlify(digestBytes)) {
    throw new Error("The ML-DSA signed message must equal the withdrawal digest");
  }
  if (!allowGeneratedMaterial && isDemoMaterial(input.publicKey, input.pqSignature)) {
    throw new Error("Real verify mode refuses generated demo PQ material");
  }
  if (!allowGeneratedMaterial && isFixtureMaterial(input.publicKey, input.pqSignature)) {
    throw new Error("Real verify mode refuses generated fixture PQ material");
  }
  const verification = verifyMLDSA65Detailed(input.publicKey, input.signedMessage, input.pqSignature);
  if (!verification.result.verified) {
    throw new Error(
      `ML-DSA-65 verification failed; attestation was not signed (reason: ${verification.result.reason})`,
    );
  }

  const publicKeyHash = hashPQPublicKey(input.publicKey);
  const pqSignatureHash = hashPQSignature(input.pqSignature);
  const { domain, value } = buildAttestation(input, publicKeyHash, pqSignatureHash);
  const attestationSignature = await attestor.signTypedData(domain, ATTESTATION_TYPES, value);
  return {
    attestationSignature,
    publicKeyHash,
    pqSignatureHash,
    verifierPayload: encodeVerifierPayload(attestationSignature, input.deadline, publicKeyHash, pqSignatureHash),
  };
}
