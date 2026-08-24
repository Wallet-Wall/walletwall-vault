import { expect } from "chai";
import type { FunctionFragment } from "ethers";
import { networkHelpers } from "./helpers/connection";
import { ethers } from "./helpers/connection";

import {
  ATTESTATION_ALGORITHM_ID,
  ATTESTATION_DOMAIN_NAME,
  ATTESTATION_DOMAIN_VERSION,
  ATTESTATION_TYPES,
  buildAttestation,
  encodeVerifierPayload,
} from "../scripts/lib/attestation";

const ALGORITHM_ID = ATTESTATION_ALGORITHM_ID;

describe("ImmutableAttestationPQCVerifier", function () {
  async function deployFixture() {
    const [deployer, attestor, other] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("ImmutableAttestationPQCVerifier");
    const verifier = await factory.deploy(attestor.address);
    await verifier.waitForDeployment();

    return { verifier, factory, deployer, attestor, other };
  }

  async function buildPayload(params: {
    verifierAddress: string;
    signer: Awaited<ReturnType<typeof ethers.getSigners>>[number];
    withdrawalDigest: string;
    publicKeyHash: string;
    pqSignatureHash: string;
    deadline: bigint;
    domainVerifyingContract?: string;
    domainChainId?: bigint;
    valueVerifier?: string;
    valueChainId?: bigint;
  }) {
    const { chainId: networkChainId } = await ethers.provider.getNetwork();
    const domain = {
      name: ATTESTATION_DOMAIN_NAME,
      version: ATTESTATION_DOMAIN_VERSION,
      chainId: params.domainChainId ?? networkChainId,
      verifyingContract: params.domainVerifyingContract ?? params.verifierAddress,
    };
    const attestation = {
      withdrawalDigest: params.withdrawalDigest,
      publicKeyHash: params.publicKeyHash,
      pqSignatureHash: params.pqSignatureHash,
      algorithmId: ALGORITHM_ID,
      verifier: params.valueVerifier ?? params.verifierAddress,
      chainId: params.valueChainId ?? networkChainId,
      deadline: params.deadline,
    };
    const attestationSignature = await params.signer.signTypedData(domain, ATTESTATION_TYPES, attestation);

    return encodeVerifierPayload(attestationSignature, params.deadline, params.publicKeyHash, params.pqSignatureHash);
  }

  async function validInputs() {
    const publicKey = ethers.hexlify(ethers.randomBytes(1952));
    const withdrawalDigest = ethers.keccak256(ethers.toUtf8Bytes("withdrawal"));
    const publicKeyHash = ethers.keccak256(publicKey);
    const pqSignatureHash = ethers.keccak256(ethers.randomBytes(3309));
    const deadline = BigInt((await networkHelpers.time.latest()) + 3600);

    return { publicKey, withdrawalDigest, publicKeyHash, pqSignatureHash, deadline };
  }

  // -------------------------------------------------------------------------
  // Constructor
  // -------------------------------------------------------------------------

  it("rejects a zero initial attestor", async function () {
    const { factory } = await deployFixture();

    await expect(factory.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(factory, "ZeroAttestor");
  });

  it("permanently records a non-zero initial attestor", async function () {
    const { verifier, attestor } = await deployFixture();

    expect(await verifier.attestor()).to.equal(attestor.address);
  });

  // -------------------------------------------------------------------------
  // Core verification (parity with AttestationPQCVerifier)
  // -------------------------------------------------------------------------

  it("accepts a valid trusted attestation", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
    });

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(true);
  });

  it("rejects an attestation from the wrong attestor", async function () {
    const { verifier, other } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: other,
      ...input,
    });

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an expired attestation", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const deadline = BigInt((await networkHelpers.time.latest()) + 10);
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
      deadline,
    });
    await networkHelpers.time.increaseTo(deadline + 1n);

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an altered withdrawal digest", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
    });
    const alteredDigest = ethers.keccak256(ethers.toUtf8Bytes("altered withdrawal"));

    expect(await verifier.verify(alteredDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an altered public key hash in the payload", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
    });
    const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["bytes", "uint256", "bytes32", "bytes32"], payload);
    const alteredPayload = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "uint256", "bytes32", "bytes32"],
      [decoded[0], decoded[1], ethers.keccak256(ethers.toUtf8Bytes("altered key")), decoded[3]],
    );

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, alteredPayload)).to.equal(false);
  });

  it("rejects when the supplied public key does not match the attested public key hash", async function () {
    // Distinct from the "altered payload" case above: here the signature is fully
    // valid over the ORIGINAL publicKeyHash. Only the raw publicKey argument passed
    // to verify() is swapped for different bytes. This isolates the direct
    // `publicKeyHash != keccak256(publicKey)` guard from the signature check — a
    // mutant that dropped only that guard would still pass every other test here
    // because the EIP-712 signature itself stays valid.
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
    });
    const differentPublicKey = ethers.hexlify(ethers.randomBytes(1952));

    expect(await verifier.verify(input.withdrawalDigest, differentPublicKey, payload)).to.equal(false);
  });

  it("rejects an altered PQ signature hash", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
    });
    const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["bytes", "uint256", "bytes32", "bytes32"], payload);
    const alteredPayload = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "uint256", "bytes32", "bytes32"],
      [decoded[0], decoded[1], decoded[2], ethers.keccak256(ethers.toUtf8Bytes("altered signature"))],
    );

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, alteredPayload)).to.equal(false);
  });

  it("rejects malformed payloads", async function () {
    const { verifier } = await deployFixture();
    const input = await validInputs();

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, "0x1234")).to.equal(false);
  });

  // -------------------------------------------------------------------------
  // Verifier-address / chain-id binding
  // -------------------------------------------------------------------------

  it("rejects an attestation signed for a different verifier address", async function () {
    const { verifier, attestor, other } = await deployFixture();
    const input = await validInputs();
    // `other` here is just used as a distinct, unrelated address for the signed
    // "verifier" field — the attestor still signs, but over the wrong contract.
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
      valueVerifier: other.address,
    });

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects a payload valid on one verifier deployment when replayed against a different deployment", async function () {
    const { verifier: verifierA, attestor, factory } = await deployFixture();
    const verifierB = await factory.deploy(attestor.address);
    await verifierB.waitForDeployment();

    const input = await validInputs();
    const payload = await buildPayload({
      verifierAddress: await verifierA.getAddress(),
      signer: attestor,
      ...input,
    });

    expect(await verifierA.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(true);
    expect(await verifierB.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an attestation whose attested chain ID does not match the current chain", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const { chainId: networkChainId } = await ethers.provider.getNetwork();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
      valueChainId: networkChainId + 1n,
    });

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an attestation signed with a mismatched EIP-712 domain chain ID", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const { chainId: networkChainId } = await ethers.provider.getNetwork();
    const payload = await buildPayload({
      verifierAddress: await verifier.getAddress(),
      signer: attestor,
      ...input,
      domainChainId: networkChainId + 1n,
    });

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("uses the attested ML-DSA-65 algorithm id, distinct from the mock verifier", async function () {
    const { verifier } = await deployFixture();
    const mockFactory = await ethers.getContractFactory("MockMLDSAVerifier");
    const mockVerifier = await mockFactory.deploy();

    expect(await verifier.algorithmId()).to.equal(ALGORITHM_ID);
    expect(await verifier.algorithmId()).not.to.equal(await mockVerifier.algorithmId());
  });

  // -------------------------------------------------------------------------
  // Immutable attestor: no rotation authority
  //
  // This is the entire point of this contract relative to AttestationPQCVerifier:
  // there is no owner, no updateAttestor, and no admin surface of any kind. The
  // only way to change the attestor is to deploy a new verifier and move the vault
  // to it through the vault's own timelocked verifier governance. See
  // docs/Attestation_Governance_Hardening.md.
  // -------------------------------------------------------------------------

  describe("Immutable attestor: no rotation authority", function () {
    it("exposes no state-mutating attestor-related function on the ABI", async function () {
      const { factory } = await deployFixture();
      const isFunctionFragment = (fragment: { type: string }): fragment is FunctionFragment =>
        fragment.type === "function";
      const attestorFragments = factory.interface.fragments
        .filter(isFunctionFragment)
        .filter((fragment) => /attestor/i.test(fragment.name));

      expect(attestorFragments.map((fragment) => fragment.name)).to.deep.equal(["attestor"]);
      expect(attestorFragments[0].stateMutability).to.equal("view");
    });

    it("exposes no ownership/admin surface on the ABI", async function () {
      const { factory } = await deployFixture();
      const isFunctionFragment = (fragment: { type: string }): fragment is FunctionFragment =>
        fragment.type === "function";
      const adminFunctionNames = ["owner", "pendingOwner", "transferOwnership", "acceptOwnership", "renounceOwnership"];
      const presentAdminFunctions = factory.interface.fragments
        .filter(isFunctionFragment)
        .map((fragment) => fragment.name)
        .filter((name) => adminFunctionNames.includes(name));

      expect(presentAdminFunctions).to.deep.equal([]);
    });

    it("has no callable path to rotate the attestor — recreates the legacy compromised-owner scenario and proves it cannot succeed", async function () {
      const { verifier, other } = await deployFixture();

      // AttestationPQCVerifier.test.ts documents: "compromised owner can install a
      // malicious attestor that signs a new digest". Here we attempt the identical
      // attack — call the rotation function a compromised owner would use — and
      // confirm there is no such function to call at all.
      expect((verifier as unknown as Record<string, unknown>).updateAttestor).to.equal(undefined);
      expect(() =>
        (verifier as unknown as { updateAttestor: (addr: string) => unknown }).updateAttestor(other.address),
      ).to.throw(TypeError);
      expect(await verifier.attestor()).to.not.equal(other.address);
    });
  });

  // -------------------------------------------------------------------------
  // Interop with existing attestation tooling
  // -------------------------------------------------------------------------

  it("accepts a payload built with the shared attestation tooling library (scripts/lib/attestation.ts)", async function () {
    const { verifier, attestor } = await deployFixture();
    const verifierAddress = await verifier.getAddress();
    const { chainId } = await ethers.provider.getNetwork();
    const input = await validInputs();

    const { domain, value } = buildAttestation(
      {
        withdrawalDigest: input.withdrawalDigest,
        publicKey: ethers.getBytes(input.publicKey),
        pqSignature: new Uint8Array(),
        signedMessage: ethers.getBytes(input.withdrawalDigest),
        verifierAddress,
        chainId,
        deadline: input.deadline,
      },
      input.publicKeyHash,
      input.pqSignatureHash,
    );
    const attestationSignature = await attestor.signTypedData(domain, ATTESTATION_TYPES, value);
    const payload = encodeVerifierPayload(
      attestationSignature,
      input.deadline,
      input.publicKeyHash,
      input.pqSignatureHash,
    );

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(true);
  });
});
