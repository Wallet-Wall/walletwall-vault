import { ethers } from "./connection";
import { withPinnedSp1Code } from "./sp1PinnedVerifier";
import { ProverClient } from "../../scripts/prover-client";

export const MOCK_PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("MOCK_VKEY"));

/** A halt principal no test signer controls (SP1-TD2): tests that are not about the halt never halt. */
export const TEST_HALT_PRINCIPAL = ethers.getAddress(ethers.dataSlice(ethers.id("test halt principal"), 12));

export async function deployMockZkVerifier() {
  const MockSP1Verifier = await ethers.getContractFactory("MockSP1Verifier");
  const mockSp1Verifier = await MockSP1Verifier.deploy();

  // The genuine wrapper over the always-accepting stand-in (no WalletWall proof exists; see sp1PinnedVerifier.ts).
  const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
  const sp1 = await mockSp1Verifier.getAddress();
  const zkVerifier = await withPinnedSp1Code(sp1, () =>
    ZKMLDSAVerifier.deploy(sp1, MOCK_PROGRAM_VKEY, TEST_HALT_PRINCIPAL),
  );

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
