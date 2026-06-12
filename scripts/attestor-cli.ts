import { Wallet, getAddress, hexlify, isAddress } from "ethers";

import type { AttestationInput } from "./lib/attestation";
// @ts-expect-error ts-node ESM requires the explicit extension.
import * as attestation from "./lib/attestation.ts";

const {
  DEMO_WARNING,
  DEMO_WITHDRAWAL_DIGEST,
  createDemoMaterial,
  normalizeWithdrawalDigest,
  parseAttestorArgs,
  readBytesInput,
  verifyAndSignAttestation,
} = attestation;

const DEMO_ATTESTOR_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEMO_VERIFIER_ADDRESS = "0x0000000000000000000000000000000000000065";

function required(values: Map<string, string>, name: string): string {
  const value = values.get(name);
  if (value === undefined) throw new Error(`Missing required --${name}`);
  return value;
}

function parsePositiveBigInt(value: string, name: string): bigint {
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error(`${name} must be positive`);
  return parsed;
}

function printResult(
  input: AttestationInput,
  attestorAddress: string,
  result: Awaited<ReturnType<typeof verifyAndSignAttestation>>,
) {
  console.log(`withdrawal digest: ${input.withdrawalDigest}`);
  console.log(`publicKeyHash: ${result.publicKeyHash}`);
  console.log(`pqSignatureHash: ${result.pqSignatureHash}`);
  console.log(`deadline: ${input.deadline}`);
  console.log(`attestor address: ${attestorAddress}`);
  console.log(`encoded verifier payload: ${result.verifierPayload}`);
}

async function runDemo() {
  console.log(DEMO_WARNING);
  console.log("The demo uses deterministic, library-generated ML-DSA-65 material.");

  const material = createDemoMaterial();
  const attestor = new Wallet(DEMO_ATTESTOR_PRIVATE_KEY);
  const input: AttestationInput = {
    withdrawalDigest: DEMO_WITHDRAWAL_DIGEST,
    publicKey: material.publicKey,
    pqSignature: material.signature,
    signedMessage: material.message,
    verifierAddress: DEMO_VERIFIER_ADDRESS,
    chainId: 31337n,
    deadline: 4_102_444_800n,
  };
  const result = await verifyAndSignAttestation(input, attestor, true);
  printResult(input, attestor.address, result);
}

async function runVerify(values: Map<string, string>) {
  const privateKey = values.get("attestor-private-key") ?? process.env.ATTESTOR_PRIVATE_KEY;
  if (privateKey === undefined) {
    throw new Error("Missing attestor key: set ATTESTOR_PRIVATE_KEY or pass --attestor-private-key");
  }

  const verifierAddress = required(values, "verifier");
  if (!isAddress(verifierAddress)) throw new Error("--verifier must be a valid EVM address");

  const withdrawalDigest = normalizeWithdrawalDigest(values.get("withdrawal-digest"));
  const publicKey = readBytesInput(values.get("public-key"), values.get("public-key-file"), "public-key");
  const pqSignature = readBytesInput(values.get("pq-signature"), values.get("pq-signature-file"), "pq-signature");
  const signedMessage = readBytesInput(values.get("message"), values.get("message-file"), "message");
  const attestor = new Wallet(privateKey);
  const input: AttestationInput = {
    withdrawalDigest,
    publicKey,
    pqSignature,
    signedMessage,
    verifierAddress: getAddress(verifierAddress),
    chainId: parsePositiveBigInt(required(values, "chain-id"), "chain-id"),
    deadline: parsePositiveBigInt(required(values, "deadline"), "deadline"),
  };

  const result = await verifyAndSignAttestation(input, attestor);
  console.log("ML-DSA-65 verification succeeded. Signing trusted attestation.");
  printResult(input, attestor.address, result);
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseAttestorArgs(args);
  if (parsed.mode === "demo") return runDemo();
  return runVerify(parsed.values);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
