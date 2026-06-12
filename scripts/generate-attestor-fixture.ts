import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { hexlify } from "ethers";

// @ts-expect-error ts-node ESM requires the explicit extension.
import * as attestation from "./lib/attestation.ts";

const { FIXTURE_SEED, FIXTURE_WITHDRAWAL_DIGEST, createFixtureMaterial, hashPQPublicKey, hashPQSignature } =
  attestation;

const outputPath = resolve("test/fixtures/mldsa/library-generated/ml-dsa-65.json");
const material = createFixtureMaterial();
const fixture = {
  source: "@noble/post-quantum 0.6.1",
  algorithm: "ML-DSA-65 / FIPS 204",
  official: false,
  seed: hexlify(FIXTURE_SEED),
  message: FIXTURE_WITHDRAWAL_DIGEST,
  publicKey: hexlify(material.publicKey),
  signature: hexlify(material.signature),
  publicKeyHash: hashPQPublicKey(material.publicKey),
  signatureHash: hashPQSignature(material.signature),
};

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(fixture, null, 2)}\n`);
writeFileSync(resolve(dirname(outputPath), "message.hex"), `${fixture.message}\n`);
writeFileSync(resolve(dirname(outputPath), "public-key.hex"), `${fixture.publicKey}\n`);
writeFileSync(resolve(dirname(outputPath), "signature.hex"), `${fixture.signature}\n`);
console.log(`Wrote ${outputPath}`);
