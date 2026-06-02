import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ethers } from "ethers";

/**
 * @title ML-DSA (Dilithium) Signer
 * @dev Handles key generation and signing using the NIST-approved ML-DSA-65 (Dilithium3).
 */
export class MLDSASigner {
  /**
   * Generates an ML-DSA-65 keypair.
   * @returns An object containing the public and private keys as Uint8Arrays.
   */
  static generateKeyPair() {
    const keys = ml_dsa65.keygen();
    return {
      publicKey: keys.publicKey,
      privateKey: keys.secretKey,
    };
  }

  /**
   * Signs a message hash using an ML-DSA-65 private key.
   * @param messageHash The 32-byte message hash (as a hex string or Uint8Array).
   * @param privateKey The ML-DSA private key (Uint8Array).
   * @returns The signature as a Uint8Array.
   */
  static sign(messageHash: string | Uint8Array, privateKey: Uint8Array): Uint8Array {
    const msg = typeof messageHash === "string" ? ethers.getBytes(messageHash) : messageHash;
    // ml_dsa65.sign expects (message, secretKey)
    // NOTE: In the noble-post-quantum source, it calls internal.sign(getMessage(msg, opts.context), secretKey, opts)
    return ml_dsa65.sign(msg, privateKey);
  }

  /**
   * Verifies an ML-DSA-65 signature.
   * @param publicKey The ML-DSA public key (Uint8Array).
   * @param messageHash The 32-byte message hash (as a hex string or Uint8Array).
   * @param signature The signature (Uint8Array).
   * @returns A boolean indicating if the signature is valid.
   */
  static verify(publicKey: Uint8Array, messageHash: string | Uint8Array, signature: Uint8Array): boolean {
    const msg = typeof messageHash === "string" ? ethers.getBytes(messageHash) : messageHash;
    return ml_dsa65.verify(signature, msg, publicKey);
  }

  /**
   * Utility to convert Uint8Array to Hex string for Solidity.
   */
  static toHex(data: Uint8Array): string {
    return ethers.hexlify(data);
  }
}
