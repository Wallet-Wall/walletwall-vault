import { network } from "hardhat";
import { runScript } from "./lib/run-script";

async function main() {
  const { ethers } = await network.create();

  const [deployer] = await ethers.getSigners();
  const chainNetwork = await ethers.provider.getNetwork();
  console.log("Deploying ZKMLDSAVerifier with account:", deployer.address);

  let sp1VerifierAddress = process.env.SP1_VERIFIER_ADDRESS;
  const allowMock = process.env.ALLOW_MOCK_SP1 === "true";
  const isLocalNetwork = chainNetwork.chainId === 31337n || chainNetwork.chainId === 1337n;

  if (sp1VerifierAddress) {
    const verifierCode = await ethers.provider.getCode(sp1VerifierAddress);
    if (verifierCode === "0x") {
      throw new Error("SP1_VERIFIER_ADDRESS must reference a deployed contract");
    }
  } else {
    if (!allowMock || !isLocalNetwork) {
      throw new Error(
        "SP1_VERIFIER_ADDRESS is required. Mock deployment is allowed only on a local chain with ALLOW_MOCK_SP1=true.",
      );
    }

    const MockSP1Verifier = await ethers.getContractFactory("MockSP1Verifier");
    const mockSp1 = await MockSP1Verifier.deploy();
    await mockSp1.waitForDeployment();
    sp1VerifierAddress = await mockSp1.getAddress();
    console.warn("TEST ONLY: deployed always-accepting MockSP1Verifier to:", sp1VerifierAddress);
  }

  let programVKey = process.env.PROGRAM_VKEY;
  if (!programVKey) {
    if (!allowMock || !isLocalNetwork) {
      throw new Error(
        "PROGRAM_VKEY is required. A mock verification key is allowed only on a local chain with ALLOW_MOCK_SP1=true.",
      );
    }
    programVKey = ethers.keccak256(ethers.toUtf8Bytes("TEST_ONLY_MOCK_VKEY"));
  }
  if (!ethers.isHexString(programVKey, 32) || programVKey === ethers.ZeroHash) {
    throw new Error("PROGRAM_VKEY must be a non-zero bytes32 value");
  }

  const ZKMLDSAVerifier = await ethers.getContractFactory("ZKMLDSAVerifier");
  const zkVerifier = await ZKMLDSAVerifier.deploy(sp1VerifierAddress, programVKey);
  await zkVerifier.waitForDeployment();

  console.log("ZKMLDSAVerifier deployed to:", await zkVerifier.getAddress());
  console.log("Program vKey:", programVKey);
}

runScript(main);
