import { ethers } from "./connection";
import { ProverClient } from "../../scripts/prover-client";

export const MOCK_PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("MOCK_VKEY"));

export async function deployMockZkVerifier() {
  const MockSP1Verifier = await ethers.getContractFactory("MockSP1Verifier");
  const mockSp1Verifier = await MockSP1Verifier.deploy();

  const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
  const zkVerifier = await ZKMLDSAVerifier.deploy(await mockSp1Verifier.getAddress(), MOCK_PROGRAM_VKEY);

  return { mockSp1Verifier, zkVerifier };
}

export async function encodeMockProof(
  zkVerifier: { getAddress(): Promise<string> },
  digest: string,
  publicKey: Uint8Array,
  signature: Uint8Array,
) {
  return ProverClient.encodeProof(
    digest,
    publicKey,
    signature,
    (await ethers.provider.getNetwork()).chainId,
    await zkVerifier.getAddress(),
    ethers.hexlify(ethers.randomBytes(128)),
  );
}
