import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying ZKMLDSAVerifier with account:", deployer.address);

  // In production, these addresses would be network-specific.
  // For local development/demo, we'd deploy a MockSP1Verifier first.
  let sp1VerifierAddress = process.env.SP1_VERIFIER_ADDRESS;

  if (!sp1VerifierAddress) {
    const MockSP1Verifier = await ethers.getContractFactory("MockSP1Verifier");
    const mockSp1 = await MockSP1Verifier.deploy();
    sp1VerifierAddress = await mockSp1.getAddress();
    console.log("Deployed MockSP1Verifier to:", sp1VerifierAddress);
  }

  const programVKey = process.env.PROGRAM_VKEY || ethers.keccak256(ethers.toUtf8Bytes("MOCK_VKEY"));

  const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
  const zkVerifier = await ZKMLDSAVerifier.deploy(sp1VerifierAddress, programVKey);
  await zkVerifier.waitForDeployment();

  console.log("ZKMLDSAVerifier deployed to:", await zkVerifier.getAddress());
  console.log("Program vKey:", programVKey);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
