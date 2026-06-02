import { ethers } from "ethers";

/**
 * @title WOTS+ Signer (Implementation)
 * @dev Implements Winternitz One-Time Signature (WOTS+) for Phase 1.
 * Using a simple version with w=16 (4 bits per chain).
 */
export class WOTSSigner {
  static readonly W = 16;
  static readonly LEN1 = 64; // 256 bits / 4 bits
  static readonly LEN2 = 3;  // Checksum length for w=16
  static readonly LEN = WOTSSigner.LEN1 + WOTSSigner.LEN2;

  /**
   * Generates a WOTS+ keypair.
   */
  static generateKeyPair(seed: Uint8Array) {
    const privateKey = new Array(this.LEN);
    const publicKey = new Array(this.LEN);

    for (let i = 0; i < this.LEN; i++) {
      privateKey[i] = ethers.solidityPackedKeccak256(
        ["bytes32", "uint256"],
        [seed, i]
      );

      let chain = privateKey[i];
      for (let j = 0; j < this.W - 1; j++) {
        chain = ethers.sha256(chain);
      }
      publicKey[i] = chain;
    }

    const publicKeyHash = ethers.keccak256(
      ethers.solidityPacked(new Array(this.LEN).fill("bytes32"), publicKey)
    );

    return { privateKey, publicKey, publicKeyHash };
  }

  /**
   * Signs a 256-bit message hash using WOTS+.
   */
  static sign(messageHash: string, privateKey: string[]): string[] {
    const msg = ethers.getBytes(messageHash);
    const lengths = this.getMessageLengths(msg);

    const signature = new Array(this.LEN);
    for (let i = 0; i < this.LEN; i++) {
      let chain = privateKey[i];
      for (let j = 0; j < lengths[i]; j++) {
        chain = ethers.sha256(chain);
      }
      signature[i] = chain;
    }
    return signature;
  }

  private static getMessageLengths(msg: Uint8Array): number[] {
    const lengths = [];
    let checksum = 0;

    for (let i = 0; i < msg.length; i++) {
      const left = (msg[i] >> 4) & 0x0f;
      const right = msg[i] & 0x0f;
      lengths.push(left);
      lengths.push(right);
      checksum += (this.W - 1 - left);
      checksum += (this.W - 1 - right);
    }

    // Checksum
    for (let i = 0; i < this.LEN2; i++) {
      const val = (checksum >> (4 * (this.LEN2 - 1 - i))) & 0x0f;
      lengths.push(val);
    }

    return lengths;
  }
}
