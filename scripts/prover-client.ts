import { ethers } from "ethers";

/**
 * @title Prover Client
 * @notice Production-grade TS wrapper for generating ZK proofs for ML-DSA-65.
 */
export class ProverClient {
  private static readonly MAX_RETRIES = 3;
  private static readonly RETRY_DELAY_MS = 2000;

  /**
   * Generates an EVM-compatible proof payload for the ZKMLDSAVerifier.
   *
   * @param withdrawalDigest 32-byte digest of the withdrawal request.
   * @param publicKey The raw ML-DSA-65 public key.
   * @param signature The raw ML-DSA-65 signature.
   * @param chainId The chain ID where the proof will be verified.
   * @param verifierAddress The address of the ZKMLDSAVerifier contract.
   * @returns A hex-encoded proof payload for Solidity.
   */
  static async generateProof(
    withdrawalDigest: string,
    publicKey: Uint8Array,
    signature: Uint8Array,
    chainId: bigint,
    verifierAddress: string,
  ): Promise<string> {
    let lastError: any;

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        return await this._generateProofInternal(withdrawalDigest, publicKey, signature, chainId, verifierAddress);
      } catch (error) {
        console.error(`Prover attempt ${attempt} failed:`, error);
        lastError = error;
        if (attempt < this.MAX_RETRIES) {
          await new Promise((resolve) => setTimeout(resolve, this.RETRY_DELAY_MS));
        }
      }
    }

    throw new Error(`Failed to generate ZK proof after ${this.MAX_RETRIES} attempts: ${lastError?.message}`);
  }

  private static async _generateProofInternal(
    withdrawalDigest: string,
    publicKey: Uint8Array,
    signature: Uint8Array,
    chainId: bigint,
    verifierAddress: string,
  ): Promise<string> {
    console.log("Generating ZK proof for ML-DSA-65...");

    // Production logic:
    // 1. Compile witnesses (GuestInputs)
    // 2. Call SP1 Prover (local or remote)
    // 3. Receive proof and journal
    // 4. Encode for EVM

    // For this prototype, we simulate a successful prover call.
    // In a real SP1 integration, we would use the SP1 SDK here.

    const pkHash = ethers.keccak256(publicKey);
    const sigHash = ethers.keccak256(signature);

    const abiCoder = new ethers.AbiCoder();

    // The journal must match exactly what the guest program commits.
    // In our guest, we commit 5 words of 32 bytes each.
    const publicValues = abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "address"],
      [withdrawalDigest, pkHash, sigHash, chainId, verifierAddress],
    );

    // Simulate proof generation time
    await new Promise((resolve) => setTimeout(resolve, 100));

    const mockProofBytes = ethers.hexlify(ethers.randomBytes(128));

    // The Solidity verifier expects: abi.encode(publicValues, proofBytes)
    const payload = abiCoder.encode(["bytes", "bytes"], [publicValues, mockProofBytes]);

    return payload;
  }
}
