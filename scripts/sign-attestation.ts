import { ethers } from "hardhat";

const REQUIRED_ATTESTOR_NOTICE =
  "In production/research use, the attestor must verify ML-DSA with a real FIPS 204-compatible implementation before signing.";

const ATTESTATION_TYPES = {
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

function bytesFromEnv(name: string, fallbackLength: number): string {
  const value = process.env[name];
  if (value !== undefined) {
    if (!ethers.isHexString(value)) {
      throw new Error(`${name} must be a 0x-prefixed hex string`);
    }
    return value;
  }

  return ethers.hexlify(ethers.randomBytes(fallbackLength));
}

async function main() {
  const [defaultSigner] = await ethers.getSigners();
  const attestor =
    process.env.ATTESTOR_PRIVATE_KEY !== undefined
      ? new ethers.Wallet(process.env.ATTESTOR_PRIVATE_KEY, ethers.provider)
      : defaultSigner;

  let verifierAddress = process.env.VERIFIER_ADDRESS;
  if (verifierAddress === undefined) {
    const factory = await ethers.getContractFactory("AttestationPQCVerifier", defaultSigner);
    const verifier = await factory.deploy(await attestor.getAddress());
    await verifier.waitForDeployment();
    verifierAddress = await verifier.getAddress();
  } else if (!ethers.isAddress(verifierAddress)) {
    throw new Error("VERIFIER_ADDRESS must be a valid EVM address");
  }

  const withdrawalDigest =
    process.env.WITHDRAWAL_DIGEST ?? ethers.keccak256(ethers.toUtf8Bytes("WalletWall sample withdrawal digest"));
  if (!ethers.isHexString(withdrawalDigest, 32)) {
    throw new Error("WITHDRAWAL_DIGEST must be a 32-byte 0x-prefixed hex string");
  }

  // These fallback bytes only demonstrate hashing and payload construction.
  // They have not been verified as an ML-DSA signature/public-key pair.
  const publicKey = bytesFromEnv("PQ_PUBLIC_KEY", 1952);
  const pqSignature = bytesFromEnv("PQ_SIGNATURE", 3309);
  const publicKeyHash = ethers.keccak256(publicKey);
  const pqSignatureHash = ethers.keccak256(pqSignature);

  const network = await ethers.provider.getNetwork();
  const chainId = process.env.CHAIN_ID === undefined ? network.chainId : BigInt(process.env.CHAIN_ID);
  const latestBlock = await ethers.provider.getBlock("latest");
  if (latestBlock === null) throw new Error("Unable to read the latest block");
  const deadline =
    process.env.ATTESTATION_DEADLINE === undefined
      ? BigInt(latestBlock.timestamp + 3600)
      : BigInt(process.env.ATTESTATION_DEADLINE);

  const algorithmId = ethers.keccak256(ethers.toUtf8Bytes("ATTESTED-ML-DSA-65"));
  const domain = {
    name: "AttestationPQCVerifier",
    version: "1",
    chainId,
    verifyingContract: verifierAddress,
  };
  const attestation = {
    withdrawalDigest,
    publicKeyHash,
    pqSignatureHash,
    algorithmId,
    verifier: verifierAddress,
    chainId,
    deadline,
  };
  const attestationSignature = await attestor.signTypedData(domain, ATTESTATION_TYPES, attestation);
  const verifierPayload = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "uint256", "bytes32", "bytes32"],
    [attestationSignature, deadline, publicKeyHash, pqSignatureHash],
  );

  console.log(REQUIRED_ATTESTOR_NOTICE);
  console.log("The generated fallback PQ bytes are mock data for payload demonstration only.");
  console.log(`withdrawal digest: ${withdrawalDigest}`);
  console.log(`publicKeyHash: ${publicKeyHash}`);
  console.log(`pqSignatureHash: ${pqSignatureHash}`);
  console.log(`deadline: ${deadline}`);
  console.log(`attestor address: ${await attestor.getAddress()}`);
  console.log(`encoded verifier payload: ${verifierPayload}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
