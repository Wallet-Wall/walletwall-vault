import { expect } from "chai";
import { networkHelpers } from "./helpers/connection";
import { ethers } from "./helpers/connection";

const ALGORITHM_ID = ethers.keccak256(ethers.toUtf8Bytes("ATTESTED-ML-DSA-65"));

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

describe("AttestationPQCVerifier", function () {
  async function deployFixture() {
    const [owner, attestor, other] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("AttestationPQCVerifier");
    const verifier = await factory.deploy(attestor.address);
    await verifier.waitForDeployment();

    return { verifier, factory, owner, attestor, other };
  }

  async function buildPayload(
    verifierAddress: string,
    signer: Awaited<ReturnType<typeof ethers.getSigners>>[number],
    withdrawalDigest: string,
    publicKeyHash: string,
    pqSignatureHash: string,
    deadline: bigint,
  ) {
    const { chainId } = await ethers.provider.getNetwork();
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
      algorithmId: ALGORITHM_ID,
      verifier: verifierAddress,
      chainId,
      deadline,
    };
    const attestationSignature = await signer.signTypedData(domain, ATTESTATION_TYPES, attestation);

    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "uint256", "bytes32", "bytes32"],
      [attestationSignature, deadline, publicKeyHash, pqSignatureHash],
    );
  }

  async function validInputs() {
    const publicKey = ethers.hexlify(ethers.randomBytes(1952));
    const withdrawalDigest = ethers.keccak256(ethers.toUtf8Bytes("withdrawal"));
    const publicKeyHash = ethers.keccak256(publicKey);
    const pqSignatureHash = ethers.keccak256(ethers.randomBytes(3309));
    const deadline = (await networkHelpers.time.latest()) + 3600;

    return {
      publicKey,
      withdrawalDigest,
      publicKeyHash,
      pqSignatureHash,
      deadline: BigInt(deadline),
    };
  }

  it("accepts a valid trusted attestation", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload(
      await verifier.getAddress(),
      attestor,
      input.withdrawalDigest,
      input.publicKeyHash,
      input.pqSignatureHash,
      input.deadline,
    );

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(true);
  });

  it("rejects an attestation from the wrong attestor", async function () {
    const { verifier, other } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload(
      await verifier.getAddress(),
      other,
      input.withdrawalDigest,
      input.publicKeyHash,
      input.pqSignatureHash,
      input.deadline,
    );

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an expired attestation", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const deadline = BigInt((await networkHelpers.time.latest()) + 10);
    const payload = await buildPayload(
      await verifier.getAddress(),
      attestor,
      input.withdrawalDigest,
      input.publicKeyHash,
      input.pqSignatureHash,
      deadline,
    );
    await networkHelpers.time.increaseTo(deadline + 1n);

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an altered withdrawal digest", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload(
      await verifier.getAddress(),
      attestor,
      input.withdrawalDigest,
      input.publicKeyHash,
      input.pqSignatureHash,
      input.deadline,
    );
    const alteredDigest = ethers.keccak256(ethers.toUtf8Bytes("altered withdrawal"));

    expect(await verifier.verify(alteredDigest, input.publicKey, payload)).to.equal(false);
  });

  it("rejects an altered public key hash", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload(
      await verifier.getAddress(),
      attestor,
      input.withdrawalDigest,
      input.publicKeyHash,
      input.pqSignatureHash,
      input.deadline,
    );
    const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["bytes", "uint256", "bytes32", "bytes32"], payload);
    const alteredPayload = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "uint256", "bytes32", "bytes32"],
      [decoded[0], decoded[1], ethers.keccak256(ethers.toUtf8Bytes("altered key")), decoded[3]],
    );

    expect(await verifier.verify(input.withdrawalDigest, input.publicKey, alteredPayload)).to.equal(false);
  });

  it("rejects an altered PQ signature hash", async function () {
    const { verifier, attestor } = await deployFixture();
    const input = await validInputs();
    const payload = await buildPayload(
      await verifier.getAddress(),
      attestor,
      input.withdrawalDigest,
      input.publicKeyHash,
      input.pqSignatureHash,
      input.deadline,
    );
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

  it("rejects a zero initial attestor", async function () {
    const { factory } = await deployFixture();

    await expect(factory.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(factory, "ZeroAttestor");
  });

  it("allows the owner to update the attestor", async function () {
    const { verifier, attestor, other } = await deployFixture();

    await expect(verifier.updateAttestor(other.address))
      .to.emit(verifier, "AttestorUpdated")
      .withArgs(attestor.address, other.address);
    expect(await verifier.attestor()).to.equal(other.address);
  });

  it("prevents a non-owner from updating the attestor", async function () {
    const { verifier, other } = await deployFixture();

    await expect(verifier.connect(other).updateAttestor(other.address))
      .to.be.revertedWithCustomError(verifier, "OwnableUnauthorizedAccount")
      .withArgs(other.address);
  });

  it("rejects a zero attestor update", async function () {
    const { verifier } = await deployFixture();

    await expect(verifier.updateAttestor(ethers.ZeroAddress)).to.be.revertedWithCustomError(verifier, "ZeroAttestor");
  });

  it("uses an algorithm id distinct from the mock verifier", async function () {
    const { verifier } = await deployFixture();
    const mockFactory = await ethers.getContractFactory("MockMLDSAVerifier");
    const mockVerifier = await mockFactory.deploy();

    expect(await verifier.algorithmId()).to.equal(ALGORITHM_ID);
    expect(await verifier.algorithmId()).not.to.equal(await mockVerifier.algorithmId());
  });

  // -------------------------------------------------------------------------
  // Ownable2Step ownership transfer
  // -------------------------------------------------------------------------

  describe("Ownable2Step ownership transfer", function () {
    it("owner can initiate a two-step ownership transfer", async function () {
      const { verifier, owner, other } = await deployFixture();

      await expect(verifier.connect(owner).transferOwnership(other.address))
        .to.emit(verifier, "OwnershipTransferStarted")
        .withArgs(owner.address, other.address);
      expect(await verifier.pendingOwner()).to.equal(other.address);
      expect(await verifier.owner()).to.equal(owner.address);
    });

    it("pending owner can accept ownership", async function () {
      const { verifier, owner, other } = await deployFixture();

      await verifier.connect(owner).transferOwnership(other.address);
      await expect(verifier.connect(other).acceptOwnership())
        .to.emit(verifier, "OwnershipTransferred")
        .withArgs(owner.address, other.address);
      expect(await verifier.owner()).to.equal(other.address);
      expect(await verifier.pendingOwner()).to.equal(ethers.ZeroAddress);
    });

    it("non-pending address cannot accept ownership", async function () {
      const { verifier, owner, other } = await deployFixture();
      const signers = await ethers.getSigners();
      const unrelated = signers[3];

      await verifier.connect(owner).transferOwnership(other.address);
      await expect(verifier.connect(unrelated).acceptOwnership()).to.be.revertedWithCustomError(
        verifier,
        "OwnableUnauthorizedAccount",
      );
    });

    it("old owner loses updateAttestor rights after ownership is accepted", async function () {
      const { verifier, owner, other } = await deployFixture();
      const [, , newAttestor] = await ethers.getSigners();

      await verifier.connect(owner).transferOwnership(other.address);
      await verifier.connect(other).acceptOwnership();

      await expect(verifier.connect(owner).updateAttestor(newAttestor.address))
        .to.be.revertedWithCustomError(verifier, "OwnableUnauthorizedAccount")
        .withArgs(owner.address);
    });

    it("new owner can call updateAttestor after acceptance", async function () {
      const { verifier, owner, other } = await deployFixture();
      const [, , newAttestor] = await ethers.getSigners();

      await verifier.connect(owner).transferOwnership(other.address);
      await verifier.connect(other).acceptOwnership();

      await expect(verifier.connect(other).updateAttestor(newAttestor.address)).to.emit(verifier, "AttestorUpdated");
      expect(await verifier.attestor()).to.equal(newAttestor.address);
    });
  });

  // -------------------------------------------------------------------------
  // Documented attack surface: immediate attestor rotation
  //
  // This test suite documents expected behavior, not a bug.
  //
  // AttestationPQCVerifier.updateAttestor is immediate: the owner can rotate
  // the attestor in a single transaction with no delay. If the verifier owner
  // is compromised, a malicious attestor can be installed instantly and begin
  // accepting fraudulent attestations from the very next block. The vault's
  // two-day verifier governance delay does NOT protect against this.
  //
  // This is the inherent trust boundary of the Phase 1 trusted-attestation
  // model. Operators must monitor AttestorUpdated events. Eliminating the risk
  // requires graduating to a ZK or chain-native verifier (see Verifier_Roadmap.md).
  // -------------------------------------------------------------------------

  describe("Documented attack surface: immediate attestor rotation (trusted-attestor model)", function () {
    it("attestor A attestations are accepted before rotation", async function () {
      const { verifier, attestor } = await deployFixture();
      const input = await validInputs();
      const payload = await buildPayload(
        await verifier.getAddress(),
        attestor,
        input.withdrawalDigest,
        input.publicKeyHash,
        input.pqSignatureHash,
        input.deadline,
      );

      expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(true);
    });

    it("owner can rotate attestor immediately to a new address", async function () {
      const { verifier, attestor, other } = await deployFixture();

      await expect(verifier.updateAttestor(other.address))
        .to.emit(verifier, "AttestorUpdated")
        .withArgs(attestor.address, other.address);
      expect(await verifier.attestor()).to.equal(other.address);
    });

    it("attestor B attestations are accepted immediately after rotation (no delay)", async function () {
      const { verifier, other } = await deployFixture();

      await verifier.updateAttestor(other.address);

      const input = await validInputs();
      const payload = await buildPayload(
        await verifier.getAddress(),
        other,
        input.withdrawalDigest,
        input.publicKeyHash,
        input.pqSignatureHash,
        input.deadline,
      );

      expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payload)).to.equal(true);
    });

    it("attestor A attestations are rejected after rotation to B (rotation is atomic)", async function () {
      const { verifier, attestor, other } = await deployFixture();

      const input = await validInputs();
      const payloadA = await buildPayload(
        await verifier.getAddress(),
        attestor,
        input.withdrawalDigest,
        input.publicKeyHash,
        input.pqSignatureHash,
        input.deadline,
      );

      await verifier.updateAttestor(other.address);

      expect(await verifier.verify(input.withdrawalDigest, input.publicKey, payloadA)).to.equal(false);
    });

    it("compromised owner can install a malicious attestor that signs a new digest — documents full attack path", async function () {
      const { verifier, other } = await deployFixture();

      // Owner is compromised; malicious attestor is installed immediately.
      await verifier.updateAttestor(other.address);

      // Malicious attestor signs a fraudulent attestation for a new digest.
      const maliciousInput = await validInputs();
      const maliciousPayload = await buildPayload(
        await verifier.getAddress(),
        other,
        maliciousInput.withdrawalDigest,
        maliciousInput.publicKeyHash,
        maliciousInput.pqSignatureHash,
        maliciousInput.deadline,
      );

      // The verifier accepts it — the attacker now controls attestation from the next block.
      expect(
        await verifier.verify(maliciousInput.withdrawalDigest, maliciousInput.publicKey, maliciousPayload),
      ).to.equal(true);
    });
  });
});
