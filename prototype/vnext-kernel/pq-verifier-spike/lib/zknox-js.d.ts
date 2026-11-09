/**
 * Minimal typings for the VENDORED, byte-identical ZKNOX client module (vendor/zknox-ethdilithium-4c370bb5/js).
 * The module is plain ESM JavaScript upstream; it is imported verbatim, so its types live here instead.
 */
declare module "*/vendor/zknox-ethdilithium-4c370bb5/js/mldsa65.js" {
  export const PARAMS: Readonly<Record<string, number>>;
  export const HALF_BYTES: number;
  export function hexToBytes(hex: string): Uint8Array;
  export function bytesToHex(bytes: Uint8Array): string;
  export function keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  export function sign(
    msg: Uint8Array,
    secretKey: Uint8Array,
    opts?: { context?: Uint8Array; deterministic?: boolean; rnd?: Uint8Array },
  ): Uint8Array;
  export function verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, context?: Uint8Array): boolean;
  export function decodePublicKey65(publicKey: Uint8Array): { rho: Uint8Array; t1: number[][] };
  export function expandPublicKey65(publicKey: Uint8Array): { aHat: bigint[][][]; t1Hat: bigint[][]; tr: Uint8Array };
  export function encodeKeyHalf65(aHatRows: bigint[][][], tr: Uint8Array, t1Polys: bigint[][]): string;
  export function encodePublicKeyBlob65(expanded: { aHat: bigint[][][]; t1Hat: bigint[][]; tr: Uint8Array }): {
    halves: string[];
    setKeyData: string;
  };
  export function publicKeyToBlob65(publicKey: Uint8Array): string;
  export function splitSignature65(sig: Uint8Array): { cTilde: Uint8Array; z: Uint8Array; h: Uint8Array };
}
