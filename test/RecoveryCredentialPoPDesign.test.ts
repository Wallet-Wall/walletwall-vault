/**
 * Executable target model for docs/Recovery_Credential_PoP_Design.md (P2).
 *
 * DESIGN + ASSURANCE ONLY. This file changes no contract and asserts no
 * behaviour that does not exist today. What it does is make the design
 * document's load-bearing claims FALSIFIABLE, so a future source change that
 * invalidates one of them reddens CI instead of quietly making the doc wrong.
 *
 * The four things it proves, and why each is discrimination rather than
 * restatement:
 *
 *  §1 THE DEFECT IS REAL — run against the REAL contracts, not a model:
 *     rotateCredentials rejects an incoming credential the caller cannot prove
 *     possession of, guardian recovery installs the identical target with no
 *     proof at all, and the resulting vault is bricked for both spending and
 *     voluntary rotation. If a future change closes the gap, these tests fail
 *     and the doc's CURRENT section is known stale.
 *
 *  §2 THE PQ LEG WOULD BE VACUOUS — run against the verifier ACTUALLY DEPLOYED
 *     (deployments/sepolia/stablecoin-vault-simulator.json wires
 *     MockMLDSAVerifier). This is the single fact the split verdict rests on,
 *     so it is proven by execution rather than by reading the mock's comments:
 *     `verify` accepts a signature produced for a different digest under a
 *     different key, and the ONLY input it discriminates on is length.
 *
 *  §3 THE ECDSA LEG IS NON-VACUOUS — a target model of the proposed EIP-712
 *     binding, with MUTANTS. A model that only restates itself proves nothing,
 *     so each mutant DROPS one bound field and the test asserts the reference
 *     binding rejects a case the mutant accepts. A mutant that cannot be
 *     distinguished from the reference is a field that was not load-bearing.
 *
 *  §4 LOCALITY AND BUDGET — that ECDSA.recover is NOT classified as an external
 *     call by the repo's own AST analyzer (which is what lets the adopted design
 *     preserve recovery locality), and that the EIP-170 arithmetic the verdict
 *     turns on is computed from a LIVE measurement, not from numbers typed into
 *     a document.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier } from "../typechain-types";
import { findExternalCallFindings } from "./helpers/astExternalCallAnalysis";
import { findContract, findFunctionDefinition, loadSourceAst } from "./helpers/solidityAst";
import { EIP170_RUNTIME_LIMIT_BYTES, measureRuntimeBytes } from "../scripts/validate-bytecode-size";

// ML-DSA-65 shapes the mock enforces (contracts/MockMLDSAVerifier.sol:39-42).
const ML_DSA_65_PUBLIC_KEY_LENGTH = 1952;
const ML_DSA_65_SIGNATURE_LENGTH = 3309;

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;

const ROTATION_TYPES = {
  RotateCredentials: [
    { name: "vaultOwner", type: "address" },
    { name: "newEcdsaSigner", type: "address" },
    { name: "newPQPublicKey", type: "bytes" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

/** A structurally-valid mock PQ signature: right length, non-zero prefix. */
const pqBlob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(ML_DSA_65_SIGNATURE_LENGTH - 1)]));
const pqKey = () => ethers.hexlify(ethers.randomBytes(ML_DSA_65_PUBLIC_KEY_LENGTH));

describe("Recovery credential proof-of-possession — P2 design model", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let owner: HardhatEthersSigner;
  let g1: HardhatEthersSigner;
  let g2: HardhatEthersSigner;
  let g3: HardhatEthersSigner;
  let controlled: HardhatEthersSigner;
  let stranger: HardhatEthersSigner;

  const PQ_KEY = pqKey();

  beforeEach(async function () {
    [owner, g1, g2, g3, controlled, stranger] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
    vault = await (await ethers.getContractFactory("WalletWallVault")).deploy(await verifier.getAddress());

    await vault.createVault(owner.address, PQ_KEY, VaultMode.Hybrid, { value: ethers.parseEther("1") });
    await vault.setGuardians([g1.address, g2.address, g3.address]);
  });

  async function vaultDomain() {
    return {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
    };
  }

  /** Drive a full guardian recovery to (newSigner, newPQKey). No proof is supplied — none exists. */
  async function recoverTo(newSigner: string, newPQKey: string) {
    await vault.connect(g1).initiateRecovery(owner.address, newSigner, newPQKey);
    await vault.connect(g1).supportRecovery(owner.address);
    await vault.connect(g2).supportRecovery(owner.address);
    await networkHelpers.time.increase(7 * 24 * 60 * 60 + 1);
    await vault.executeRecovery(owner.address);
  }

  // ===========================================================================
  // §1 — the defect, against the real contracts
  // ===========================================================================
  describe("§1 CURRENT — rotation demands incoming possession; recovery does not", function () {
    it("rotateCredentials REJECTS an incoming ECDSA credential the caller cannot prove", async function () {
      const domain = await vaultDomain();
      const newPQ = pqKey();
      const request = {
        vaultOwner: owner.address,
        newEcdsaSigner: stranger.address, // target we do NOT control
        newPQPublicKey: newPQ,
        nonce: Number(await vault.nonces(owner.address)),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const auth = {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, request),
        currentPqSignature: pqBlob(),
        // The incoming proof is signed by the WRONG key — this is exactly the
        // mistake guardian recovery cannot detect.
        newEcdsaSignature: await controlled.signTypedData(domain, ROTATION_TYPES, request),
        newPqSignature: pqBlob(),
      };

      await expect(
        vault.rotateCredentials(owner.address, stranger.address, newPQ, request.deadline, auth),
      ).to.be.revertedWithCustomError(vault, "InvalidNewEcdsaProof");
    });

    it("guardian recovery ACCEPTS the identical target with no proof of any kind", async function () {
      const newPQ = pqKey();
      await recoverTo(stranger.address, newPQ);

      const v = await vault.getVault(owner.address);
      expect(v.ecdsaSigner, "recovery installed an unproven ECDSA signer").to.equal(stranger.address);
      expect(v.pqPublicKey, "recovery installed an unproven PQ key").to.equal(newPQ);
    });

    it("initiateRecovery's ABI carries no proof parameter — P2 is specified, not implemented", async function () {
      // The machine-checkable form of the doc's "no contracts/** change" claim.
      // If a future lane implements the ECDSA leg, this fails and the design
      // document's TARGET/RESIDUAL split must be revisited alongside it.
      const fragment = vault.interface.getFunction("initiateRecovery");
      expect(fragment.inputs.map((i) => i.type)).to.deep.equal(["address", "address", "bytes"]);
    });

    it("recovering to an UNUSABLE PQ key bricks both spending and voluntary rotation (the §1.3 cost)", async function () {
      // A 4-byte PQ key passes _validateCredentials (non-empty) and is installed.
      const junkPQ = "0xdeadbeef";
      await recoverTo(controlled.address, junkPQ);
      expect((await vault.getVault(owner.address)).pqPublicKey).to.equal(junkPQ);

      const domain = await vaultDomain();
      const nonce = Number(await vault.nonces(owner.address));
      const deadline = (await networkHelpers.time.latest()) + 3600;

      // Spending is dead: the mock rejects a 4-byte key outright.
      const wRequest = {
        vaultOwner: owner.address,
        recipient: stranger.address,
        amount: ethers.parseEther("0.1"),
        nonce,
        deadline,
        vaultMode: VaultMode.Hybrid,
      };
      const wTypes = {
        Withdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "vaultMode", type: "uint8" },
        ],
      };
      await expect(
        vault.withdraw(wRequest, await controlled.signTypedData(domain, wTypes, wRequest), pqBlob()),
      ).to.be.revertedWithCustomError(vault, "InvalidPQSignature");

      // And the self-repair path is dead with it: rotateCredentials needs the
      // CURRENT PQ credential to co-sign, and the current PQ credential is junk.
      const rRequest = {
        vaultOwner: owner.address,
        newEcdsaSigner: controlled.address,
        newPQPublicKey: PQ_KEY,
        nonce,
        deadline,
      };
      await expect(
        vault.rotateCredentials(owner.address, controlled.address, PQ_KEY, deadline, {
          currentEcdsaSignature: await controlled.signTypedData(domain, ROTATION_TYPES, rRequest),
          currentPqSignature: pqBlob(),
          newEcdsaSignature: await controlled.signTypedData(domain, ROTATION_TYPES, rRequest),
          newPqSignature: pqBlob(),
        }),
      ).to.be.revertedWithCustomError(vault, "InvalidPQSignature");

      // The exit is another full recovery cycle — bounded, not permanent.
      await recoverTo(controlled.address, pqKey());
      expect((await vault.getVault(owner.address)).pqPublicKey).to.have.lengthOf(2 + ML_DSA_65_PUBLIC_KEY_LENGTH * 2);
    });
  });

  // ===========================================================================
  // §2 — a PQ PoP would be vacuous under the verifier actually deployed
  // ===========================================================================
  describe("§2 the PQ leg carries no possession information under the deployed verifier", function () {
    it("verify() accepts a signature produced for a DIFFERENT digest and a DIFFERENT key", async function () {
      const digestA = ethers.keccak256(ethers.toUtf8Bytes("recovery target A"));
      const keyA = pqKey();
      const keyB = pqKey();
      const unrelatedSignature = pqBlob();

      // The same blob "proves possession" of two unrelated keys over an
      // unrelated digest. A PoP check built on this predicate learns nothing.
      expect(await verifier.verify(digestA, keyA, unrelatedSignature)).to.equal(true);
      expect(await verifier.verify(digestA, keyB, unrelatedSignature)).to.equal(true);
      expect(
        await verifier.verify(ethers.keccak256(ethers.toUtf8Bytes("target B")), keyA, unrelatedSignature),
      ).to.equal(true);
    });

    it("verify() is CONSTANT over correctly-sized inputs — it discriminates on length alone", async function () {
      const digest = ethers.keccak256(ethers.toUtf8Bytes("d"));
      const sig = pqBlob();

      // Every correctly-sized key passes...
      for (let i = 0; i < 4; i++) {
        expect(await verifier.verify(digest, pqKey(), sig)).to.equal(true);
      }

      // ...and the ONLY thing that fails is a wrong length. That is precisely
      // the hardcoded ML-DSA-65 length assertion the repository already struck
      // (docs/Guardian_Authority_Design.md S-3), wearing a possession error's name.
      expect(await verifier.verify(digest, "0xdeadbeef", sig)).to.equal(false);
      expect(await verifier.verify(digest, pqKey(), "0x01020304")).to.equal(false);
    });

    it("1952 bytes of noise are indistinguishable from a real key, so no adversary is constrained", async function () {
      const digest = ethers.keccak256(ethers.toUtf8Bytes("d"));
      expect(await verifier.verify(digest, ethers.hexlify(ethers.randomBytes(1952)), pqBlob())).to.equal(true);
    });
  });

  // ===========================================================================
  // §3 — target model of the ECDSA leg, with mutation kills
  // ===========================================================================
  describe("§3 TARGET — the proposed ECDSA binding, and what each bound field buys", function () {
    // The reference binding from docs/Recovery_Credential_PoP_Design.md §8.
    // NOTE the deliberate absence of any credential-movable counter (§8.1):
    // binding vault.nonce would hand a credential thief a rotation-powered veto.
    const REFERENCE_TYPES = {
      RecoveryTargetPoP: [
        { name: "vaultOwner", type: "address" },
        { name: "newEcdsaSigner", type: "address" },
        { name: "newPQPublicKeyHash", type: "bytes32" },
        { name: "vaultMode", type: "uint8" },
        { name: "deadline", type: "uint256" },
      ],
    };

    // Each mutant DROPS exactly one bound field. A mutant that still rejects
    // everything the reference rejects proves that field was not load-bearing.
    const MUTANTS = {
      M3_no_owner_binding: REFERENCE_TYPES.RecoveryTargetPoP.filter((f) => f.name !== "vaultOwner"),
      M5_no_pq_hash_binding: REFERENCE_TYPES.RecoveryTargetPoP.filter((f) => f.name !== "newPQPublicKeyHash"),
      M6_no_deadline_binding: REFERENCE_TYPES.RecoveryTargetPoP.filter((f) => f.name !== "deadline"),
      M7_no_target_binding: REFERENCE_TYPES.RecoveryTargetPoP.filter((f) => f.name !== "newEcdsaSigner"),
    };

    type Statement = {
      vaultOwner: string;
      newEcdsaSigner: string;
      newPQPublicKeyHash: string;
      vaultMode: number;
      deadline: number;
    };

    function baseStatement(overrides: Partial<Statement> = {}): Statement {
      return {
        vaultOwner: owner.address,
        newEcdsaSigner: controlled.address,
        newPQPublicKeyHash: ethers.keccak256(PQ_KEY),
        vaultMode: VaultMode.Hybrid,
        deadline: 4_000_000_000,
        ...overrides,
      };
    }

    function projected(fields: { name: string; type: string }[], s: Statement): Record<string, unknown> {
      return Object.fromEntries(fields.map((f) => [f.name, (s as Record<string, unknown>)[f.name]]));
    }

    /**
     * Verify a statement under a given field set. Returns the recovered signer,
     * which the vault would compare against `newEcdsaSigner`.
     */
    async function recoverUnder(
      fields: { name: string; type: string }[],
      signer: HardhatEthersSigner,
      signed: Statement,
      presented: Statement,
      domainOverride?: Record<string, unknown>,
    ): Promise<string> {
      const domain = domainOverride ?? (await vaultDomain());
      const types = { RecoveryTargetPoP: fields };
      const signature = await signer.signTypedData(domain, types, projected(fields, signed));
      return ethers.verifyTypedData(domain, types, projected(fields, presented), signature);
    }

    const REF = REFERENCE_TYPES.RecoveryTargetPoP;

    it("scenario 1 — the holder of the incoming key produces a proof that verifies", async function () {
      const s = baseStatement();
      expect(await recoverUnder(REF, controlled, s, s)).to.equal(controlled.address);
    });

    it("scenario 2 — a proof signed by the WRONG key does not verify as the target", async function () {
      const s = baseStatement();
      expect(await recoverUnder(REF, stranger, s, s)).to.not.equal(controlled.address);
    });

    it("scenario 9 — a proof for this vault does not verify against the simulator's domain", async function () {
      const s = baseStatement();
      const simulatorDomain = {
        name: "WalletWallStablecoinVault", // the simulator's own EIP-712 name
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await vault.getAddress(),
      };
      const signature = await controlled.signTypedData(await vaultDomain(), REFERENCE_TYPES, projected(REF, s));
      expect(
        ethers.verifyTypedData(simulatorDomain, REFERENCE_TYPES, projected(REF, s), signature),
        "domain separator must isolate the two contracts",
      ).to.not.equal(controlled.address);
    });

    it("scenario 9b — a proof does not verify against a different chainId", async function () {
      const s = baseStatement();
      const domain = await vaultDomain();
      const signature = await controlled.signTypedData(domain, REFERENCE_TYPES, projected(REF, s));
      expect(
        ethers.verifyTypedData({ ...domain, chainId: 999n }, REFERENCE_TYPES, projected(REF, s), signature),
      ).to.not.equal(controlled.address);
    });

    it("M3 KILLED — dropping vaultOwner lets one owner's proof verify for another", async function () {
      const signed = baseStatement();
      const presented = baseStatement({ vaultOwner: stranger.address });

      // Reference: the substitution is detected.
      expect(await recoverUnder(REF, controlled, signed, presented)).to.not.equal(controlled.address);
      // Mutant: it is not.
      expect(await recoverUnder(MUTANTS.M3_no_owner_binding, controlled, signed, presented)).to.equal(
        controlled.address,
      );
    });

    it("M5 KILLED — dropping the PQ-key hash lets a guardian swap the PQ half of the pair", async function () {
      const signed = baseStatement();
      const presented = baseStatement({ newPQPublicKeyHash: ethers.keccak256(pqKey()) });

      expect(await recoverUnder(REF, controlled, signed, presented)).to.not.equal(controlled.address);
      expect(await recoverUnder(MUTANTS.M5_no_pq_hash_binding, controlled, signed, presented)).to.equal(
        controlled.address,
      );
    });

    it("M6 KILLED — dropping the deadline makes a proof bankable forever", async function () {
      const signed = baseStatement();
      const presented = baseStatement({ deadline: 9_000_000_000 });

      expect(await recoverUnder(REF, controlled, signed, presented)).to.not.equal(controlled.address);
      expect(await recoverUnder(MUTANTS.M6_no_deadline_binding, controlled, signed, presented)).to.equal(
        controlled.address,
      );
    });

    it("M7 KILLED — dropping newEcdsaSigner lets a proof for target A be presented for target B", async function () {
      const signed = baseStatement();
      const presented = baseStatement({ newEcdsaSigner: stranger.address });

      expect(await recoverUnder(REF, controlled, signed, presented)).to.not.equal(controlled.address);
      expect(await recoverUnder(MUTANTS.M7_no_target_binding, controlled, signed, presented)).to.equal(
        controlled.address,
      );
    });

    it("scenario 13 — a proof predates a credential rotation and REMAINS valid (deliberate, §8.1)", async function () {
      const s = baseStatement();
      const before = await recoverUnder(REF, controlled, s, s);

      // Rotate the vault's credentials: vault.nonce moves.
      const domain = await vaultDomain();
      const nextPQ = pqKey();
      const req = {
        vaultOwner: owner.address,
        newEcdsaSigner: g3.address,
        newPQPublicKey: nextPQ,
        nonce: Number(await vault.nonces(owner.address)),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      await vault.rotateCredentials(owner.address, g3.address, nextPQ, req.deadline, {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, req),
        currentPqSignature: pqBlob(),
        newEcdsaSignature: await g3.signTypedData(domain, ROTATION_TYPES, req),
        newPqSignature: pqBlob(),
      });
      expect(await vault.nonces(owner.address), "rotation must have moved the nonce").to.be.greaterThan(0);

      // The proof still verifies. Binding vault.nonce would have voided it here —
      // and a credential THIEF can call rotateCredentials, so that would be a
      // rotation-powered veto over the remedy for their own theft.
      expect(await recoverUnder(REF, controlled, s, s))
        .to.equal(before)
        .and.to.equal(controlled.address);
    });

    it("scenario 8 — PqOnly demands no ECDSA proof: the mandatory set matches the mode's own needs", async function () {
      // Mirrors _authorizeRotation's needEcdsa/needPq derivation (:748-750).
      const mandatory = (mode: number) => ({
        ecdsa: mode === VaultMode.EcdsaOnly || mode === VaultMode.Hybrid,
        pq: mode === VaultMode.PqOnly || mode === VaultMode.Hybrid,
      });
      expect(mandatory(VaultMode.EcdsaOnly)).to.deep.equal({ ecdsa: true, pq: false });
      expect(mandatory(VaultMode.PqOnly)).to.deep.equal({ ecdsa: false, pq: true });
      expect(mandatory(VaultMode.Hybrid)).to.deep.equal({ ecdsa: true, pq: true });
    });
  });

  // ===========================================================================
  // §4 — locality and budget
  // ===========================================================================
  describe("§4 locality and EIP-170 budget", function () {
    const CONTRACTS = [
      { name: "WalletWallVault", path: "contracts/WalletWallVault.sol" },
      { name: "StablecoinVaultSimulator", path: "contracts/StablecoinVaultSimulator.sol" },
    ];

    it("ECDSA.recover is NOT classified as an external call — this is what lets the design keep locality", function () {
      // _authorizeRotation contains BOTH `digest.recover(...)` and
      // `pqVerifier.verify(...)`. If the analyzer flagged `recover`, the adopted
      // design could not preserve recovery locality at all. Asserting that the
      // findings are exactly the verifier calls proves the distinction is real
      // and is not an artifact of the function being call-free.
      for (const { name, path } of CONTRACTS) {
        const fn = findFunctionDefinition(findContract(loadSourceAst(path), name), "_authorizeRotation");
        const findings = findExternalCallFindings(fn.body);
        expect(findings.length, `${name}: expected only verifier calls`).to.be.greaterThan(0);
        for (const f of findings) {
          expect(f.memberName, `${name}: unexpected external call classified`).to.equal("verify");
        }
      }
    });

    it("recovery is callback-free today, so the adopted design narrows no invariant", function () {
      for (const { name, path } of CONTRACTS) {
        const contractAst = findContract(loadSourceAst(path), name);
        for (const fn of ["initiateRecovery", "supportRecovery", "executeRecovery", "cancelRecovery"]) {
          const findings = findExternalCallFindings(findFunctionDefinition(contractAst, fn).body);
          expect(findings, `${name}.${fn}`).to.deep.equal([]);
        }
      }
    });

    it("the §11.5 budget gate is computed from a LIVE measurement, not from typed-in numbers", function () {
      const vaultBytes = measureRuntimeBytes("WalletWallVault.sol/WalletWallVault.json", "P2 design");
      const headroom = EIP170_RUNTIME_LIMIT_BYTES - vaultBytes;

      // Constants sourced from the OTHER lane's own published measurement and
      // stop condition, not invented here.
      const GUARDIAN_AUTHORITY_CONSUMER_BYTES = 406;
      const REPO_HEADROOM_FLOOR_BYTES = 600;
      // Measured cost of the cheapest sound P2 design (spike V1, docs §11.2).
      const CHEAPEST_SOUND_P2_BYTES = 464;

      const budgetForP2 = headroom - GUARDIAN_AUTHORITY_CONSUMER_BYTES - REPO_HEADROOM_FLOOR_BYTES;

      // The verdict: P2 does not fit alongside the Guardian Authority consumer.
      // If a future change frees enough bytes, THIS TEST FAILS — which is the
      // signal to revisit the design document's §7 verdict, not to edit a number.
      expect(
        budgetForP2,
        `available budget ${budgetForP2}B vs cheapest sound design ${CHEAPEST_SOUND_P2_BYTES}B — ` +
          "if this is no longer a shortfall, docs/Recovery_Credential_PoP_Design.md §7/§11.5 must be re-adjudicated",
      ).to.be.lessThan(CHEAPEST_SOUND_P2_BYTES);
    });

    it("no production contract in this PR exceeds the EIP-170 ceiling (P2 ships zero Solidity)", function () {
      for (const { name } of CONTRACTS) {
        const bytes = measureRuntimeBytes(`${name}.sol/${name}.json`, "P2 design");
        expect(bytes, `${name} runtime bytes`).to.be.at.most(EIP170_RUNTIME_LIMIT_BYTES);
      }
    });
  });
});
