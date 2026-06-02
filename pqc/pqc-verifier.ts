import { ethers } from "ethers";

/**
 * @title WOTS+ Verifier (Implementation)
 * @dev Implements WOTS+ verification logic.
 */
export class WOTSVerifier {
  static readonly W = 16;
  static readonly LEN1 = 64;
  static readonly LEN2 = 3;
  static readonly LEN = WOTSVerifier.LEN1 + WOTSVerifier.LEN2;

  /**
   * Recovers the WOTS+ public key from a signature and message hash.
   */
  static recoverPublicKey(messageHash: string, signature: string[]): string[] {
    const msg = ethers.getBytes(messageHash);
    const lengths = this.getMessageLengths(msg);

    const recoveredPubKey = new Array(this.LEN);
    for (let i = 0; i < this.LEN; i++) {
      let chain = signature[i];
      for (let j = lengths[i]; j < this.W - 1; j++) {
        chain = ethers.sha256(chain);
      }
      recoveredPubKey[i] = chain;
    }
    return recoveredPubKey;
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

    for (let i = 0; i < this.LEN2; i++) {
      const val = (checksum >> (4 * (this.LEN2 - 1 - i))) & 0x0f;
      lengths.push(val);
    }

    return lengths;
  }
}
