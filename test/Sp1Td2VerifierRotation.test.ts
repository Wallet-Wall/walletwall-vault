/**
 * SP1-TD2 — the rotation side of the halt (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
 *
 * Recovery from a halted wrapper is a new wrapper of an independently established identity, installed through the
 * consumer's own delayed rotation. Every consumer that rotates enforces on chain (contracts/verifiers/
 * VerifierRotationGuard.sol), and this suite proves for each of WalletWallVault and StablecoinVaultSimulator (in
 * the halt's scope, TD2-COMMON-VERIFIER-HALT) and WalletWallMultiSigVault (TD2-MULTISIG-ROTATION):
 *
 *   HALT_PRINCIPAL_CANNOT_ROTATE_EVEN_AFTER_AN_OWNERSHIP_TRANSFER — enforced in code: an account that can halt
 *     the consumer's current or pending verifier can never complete an ownership transfer to itself, and can
 *     never drive a rotation.
 *   HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET (vaults in scope) / ..._AS_A_ROTATION_TARGET (multisig) — a
 *     halted wrapper and a fresh deployment of its identity (SP1 verifier code hash, PROGRAM_VKEY) are refused.
 *
 * and, for the multisig vault's new rotation (the owner's frozen items 1-8):
 *
 *   HALTED_THEN_ROTATED_WITHDRAWAL_SUCCEEDS — halted, the multisig cannot withdraw through the old wrapper;
 *     after the delay and a rotation to a fresh valid wrapper, the same authorization succeeds.
 *   MALICIOUS_REPLACEMENT_BLOCKED_OUTSIDE_DELAYED_PATH — an accept-all replacement cannot be activated except
 *     through the full delay, and only by the owner; and, executed rather than asserted, what the delayed path
 *     itself lets the owner do (the authorization cut: NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL).
 *
 * Every refusal has a positive control: the same step with the one disqualifying fact removed succeeds.
 */
import { expect } from "chai";

import { ethers, networkHelpers } from "./helpers/connection";
import { findContract, loadSourceAst, walkAst, type AstNode } from "./helpers/solidityAst";
import {
  GRACE_PERIOD,
  ROTATION_DELAY,
  VKEY_A,
  VKEY_B,
  deploySp1,
  deployWrapper,
  mlDsaKey,
  mlDsaSign,
  mutatingFunctions,
  proveFor,
  type MlDsaKey,
} from "./helpers/td2Helpers";

type Consumer = {
  name: "WalletWallVault" | "StablecoinVaultSimulator" | "WalletWallMultiSigVault";
  /** The proof id this consumer's identity refusal discharges. */
  identityProof: "HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET" | "HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET";
  deploy: (verifier: string, deployer: any) => Promise<any>;
};

/** MisbehavingVerifierMock behaviours, by ordinal, and the selectors of the halt surface it answers for. */
const B = {
  Revert: 0,
  Return: 1,
  RevertWithWord: 2,
  ReturnShort: 3,
  BurnGas: 4,
  ReturnHuge: 5,
  ReturnOwner: 6,
  ReturnPendingOwner: 7,
} as const;
const SEL = {
  HALT_PRINCIPAL: ethers.id("HALT_PRINCIPAL()").slice(0, 10),
  halted: ethers.id("halted()").slice(0, 10),
  SP1_VERIFIER: ethers.id("SP1_VERIFIER()").slice(0, 10),
  PROGRAM_VKEY: ethers.id("PROGRAM_VKEY()").slice(0, 10),
} as const;
/** An address (or small number) as a clean 32-byte word. */
const word = (value: string) => ethers.zeroPadValue(value, 32);

/** keccak256(abi.encode(EXTCODEHASH(SP1 verifier), PROGRAM_VKEY)), computed from the chain, not from the guard. */
async function identityOf(wrapper: any): Promise<string> {
  const code = await ethers.provider.getCode(await wrapper.SP1_VERIFIER());
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [ethers.keccak256(code), await wrapper.PROGRAM_VKEY()],
    ),
  );
}

describe("SP1-TD2 verifier rotation: halt principal and halted identity (every rotating consumer)", function () {
  let admin: any, haltPrincipal: any, successor: any, attacker: any, otherHaltPrincipal: any;
  let token: any;

  const CONSUMERS: Consumer[] = [
    {
      name: "WalletWallVault",
      identityProof: "HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET",
      deploy: async (verifier, deployer) =>
        (await ethers.getContractFactory("WalletWallVault", deployer)).deploy(verifier),
    },
    {
      name: "StablecoinVaultSimulator",
      identityProof: "HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET",
      deploy: async (verifier, deployer) =>
        (await ethers.getContractFactory("StablecoinVaultSimulator", deployer)).deploy(
          await token.getAddress(),
          verifier,
        ),
    },
    {
      name: "WalletWallMultiSigVault",
      identityProof: "HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET",
      deploy: async (verifier, deployer) =>
        (await ethers.getContractFactory("WalletWallMultiSigVault", deployer)).deploy(verifier),
    },
  ];

  beforeEach(async function () {
    [admin, haltPrincipal, successor, attacker, otherHaltPrincipal] = await ethers.getSigners();
    token = await (await ethers.getContractFactory("MockUSDC")).deploy();
  });

  for (const c of CONSUMERS) {
    describe(c.name, function () {
      let sp1: any, w1: any, w2: any, consumer: any;

      beforeEach(async function () {
        sp1 = await deploySp1();
        w1 = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
        // Independently established: another program build (another vkey), its own halt principal.
        w2 = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
        consumer = await c.deploy(await w1.getAddress(), admin);
      });

      const rotateTo = async (target: any) => {
        await consumer.connect(admin).proposePQVerifier(await target.getAddress());
        await networkHelpers.time.increase(ROTATION_DELAY);
        await consumer.connect(admin).applyPQVerifierUpdate();
      };

      describe("HALT_PRINCIPAL_CANNOT_ROTATE_EVEN_AFTER_AN_OWNERSHIP_TRANSFER", function () {
        it(`${c.name}: the halt principal cannot propose, apply or cancel a rotation (it is not the owner)`, async function () {
          await expect(
            consumer.connect(haltPrincipal).proposePQVerifier(await w2.getAddress()),
          ).to.be.revertedWithCustomError(consumer, "OwnableUnauthorizedAccount");
          await consumer.connect(admin).proposePQVerifier(await w2.getAddress()); // positive control: the owner can
          for (const fn of ["applyPQVerifierUpdate", "cancelPQVerifierUpdate"]) {
            await expect(consumer.connect(haltPrincipal).getFunction(fn)()).to.be.revertedWithCustomError(
              consumer,
              "OwnableUnauthorizedAccount",
            );
          }
        });

        it(`${c.name}: an ownership transfer to the halt principal never completes, before or after the halt; any other successor's does`, async function () {
          for (const phase of ["while ACTIVE", "after the halt"]) {
            if (phase === "after the halt") await w1.connect(haltPrincipal).halt();
            await consumer.connect(admin).transferOwnership(haltPrincipal.address);
            await expect(consumer.connect(haltPrincipal).acceptOwnership(), phase)
              .to.be.revertedWithCustomError(consumer, "HaltPrincipalCannotGovern")
              .withArgs(haltPrincipal.address);
            expect(await consumer.owner(), phase).to.equal(admin.address);
            await expect(
              consumer.connect(haltPrincipal).proposePQVerifier(await w2.getAddress()),
              phase,
            ).to.be.revertedWithCustomError(consumer, "OwnableUnauthorizedAccount");
          }
          // Positive control: the same two-step transfer to anyone else completes, and that owner can rotate.
          await consumer.connect(admin).transferOwnership(successor.address);
          await consumer.connect(successor).acceptOwnership();
          expect(await consumer.owner()).to.equal(successor.address);
          await consumer.connect(successor).proposePQVerifier(await w2.getAddress());
          expect(await consumer.pendingPQVerifier()).to.equal(await w2.getAddress());
        });

        it(`${c.name}: the owner cannot propose a wrapper it could halt (it would hold both levers once applied)`, async function () {
          const ownedByAdmin = await deployWrapper(sp1, VKEY_B, admin.address);
          await expect(consumer.connect(admin).proposePQVerifier(await ownedByAdmin.getAddress()))
            .to.be.revertedWithCustomError(consumer, "HaltPrincipalCannotGovern")
            .withArgs(admin.address);
          await consumer.connect(admin).proposePQVerifier(await w2.getAddress()); // positive control
        });

        it(`${c.name}: a pending owner who can halt the pending verifier cannot accept until that proposal is gone`, async function () {
          const haltableBySuccessor = await deployWrapper(sp1, VKEY_B, successor.address);
          await consumer.connect(admin).transferOwnership(successor.address);
          await consumer.connect(admin).proposePQVerifier(await haltableBySuccessor.getAddress());
          await expect(consumer.connect(successor).acceptOwnership())
            .to.be.revertedWithCustomError(consumer, "HaltPrincipalCannotGovern")
            .withArgs(successor.address);
          await consumer.connect(admin).cancelPQVerifierUpdate();
          await consumer.connect(successor).acceptOwnership(); // positive control
          expect(await consumer.owner()).to.equal(successor.address);
        });

        it(`${c.name}: the halt principal cannot deploy the consumer over its own wrapper (it would own it from birth)`, async function () {
          const factory = await ethers.getContractFactory(c.name);
          await expect(c.deploy(await w1.getAddress(), haltPrincipal))
            .to.be.revertedWithCustomError(factory, "HaltPrincipalCannotGovern")
            .withArgs(haltPrincipal.address);
          await c.deploy(await w1.getAddress(), successor); // positive control
        });
      });

      describe(c.identityProof, function () {
        it(`${c.name}: the halted wrapper itself is refused as a target`, async function () {
          await w1.connect(haltPrincipal).halt();
          await expect(consumer.connect(admin).proposePQVerifier(await w1.getAddress()))
            .to.be.revertedWithCustomError(consumer, "HaltedVerifierTarget")
            .withArgs(await w1.getAddress());
          await consumer.connect(admin).proposePQVerifier(await w2.getAddress()); // positive control
        });

        it(`${c.name}: a fresh deployment of the halted identity is refused, whatever its address or halt principal`, async function () {
          await w1.connect(haltPrincipal).halt();
          const sameSp1 = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
          const sameCodeElsewhere = await deployWrapper(await deploySp1(), VKEY_A, haltPrincipal.address);
          const identity = await identityOf(w1);
          for (const fresh of [sameSp1, sameCodeElsewhere]) {
            expect(await identityOf(fresh)).to.equal(identity);
            await expect(consumer.connect(admin).proposePQVerifier(await fresh.getAddress()))
              .to.be.revertedWithCustomError(consumer, "HaltedVerifierIdentity")
              .withArgs(await fresh.getAddress(), identity);
          }
          // Positive control: an independently established identity (another program build) is accepted.
          expect(await identityOf(w2)).to.not.equal(identity);
          await consumer.connect(admin).proposePQVerifier(await w2.getAddress());
        });

        it(`${c.name}: recovery to an independent identity succeeds after the delay, and the halted identity stays refused for good`, async function () {
          await w1.connect(haltPrincipal).halt();
          await consumer.connect(admin).proposePQVerifier(await w2.getAddress());
          await expect(consumer.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
            consumer,
            "PQVerifierUpdateNotReady",
          );
          await networkHelpers.time.increase(ROTATION_DELAY);
          await expect(consumer.connect(admin).applyPQVerifierUpdate())
            .to.emit(consumer, "PQVerifierUpdated")
            .withArgs(await w1.getAddress(), await w2.getAddress());
          expect(await consumer.pqVerifier()).to.equal(await w2.getAddress());
          const identity = await identityOf(w1);
          expect(await consumer.haltedVerifierIdentities(identity)).to.equal(true);
          expect(await w1.halted(), "the old wrapper stays HALTED (no HALTED -> ACTIVE)").to.equal(true);
          // The current wrapper is no longer the halted one, yet the identity is still refused (recorded on chain).
          const fresh = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
          await expect(consumer.connect(admin).proposePQVerifier(await fresh.getAddress()))
            .to.be.revertedWithCustomError(consumer, "HaltedVerifierIdentity")
            .withArgs(await fresh.getAddress(), identity);
          await expect(consumer.connect(admin).proposePQVerifier(await w1.getAddress())).to.be.revertedWithCustomError(
            consumer,
            "HaltedVerifierTarget",
          );
        });

        it(`${c.name}: a target halted during the delay is refused at apply, and the proposal stays cancellable`, async function () {
          await consumer.connect(admin).proposePQVerifier(await w2.getAddress());
          await w2.connect(otherHaltPrincipal).halt();
          await networkHelpers.time.increase(ROTATION_DELAY);
          await expect(consumer.connect(admin).applyPQVerifierUpdate())
            .to.be.revertedWithCustomError(consumer, "HaltedVerifierTarget")
            .withArgs(await w2.getAddress());
          expect(await consumer.pqVerifier()).to.equal(await w1.getAddress());
          expect(await consumer.pendingPQVerifier()).to.equal(await w2.getAddress());
          await consumer.connect(admin).cancelPQVerifierUpdate();
          expect(await consumer.pendingPQVerifier()).to.equal(ethers.ZeroAddress);
        });

        it(`${c.name}: once the current wrapper is halted, a pending target of its identity is refused at apply`, async function () {
          // Proposed while w1 was ACTIVE (a same-identity redeploy is admissible then, e.g. a new halt principal).
          const sameIdentity = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
          await consumer.connect(admin).proposePQVerifier(await sameIdentity.getAddress());
          await w1.connect(haltPrincipal).halt();
          await networkHelpers.time.increase(ROTATION_DELAY);
          await expect(consumer.connect(admin).applyPQVerifierUpdate())
            .to.be.revertedWithCustomError(consumer, "HaltedVerifierIdentity")
            .withArgs(await sameIdentity.getAddress(), await identityOf(w1));
        });

        it(`${c.name}: positive control for the redeploy itself: while the current wrapper is ACTIVE a same-identity rotation applies`, async function () {
          const sameIdentity = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
          await rotateTo(sameIdentity);
          expect(await consumer.pqVerifier()).to.equal(await sameIdentity.getAddress());
          expect(await consumer.haltedVerifierIdentities(await identityOf(w1))).to.equal(false);
        });
      });

      describe("no verifier can veto its own replacement (the guard never strands a consumer)", function () {
        let hostile: any;

        beforeEach(async function () {
          hostile = await (await ethers.getContractFactory("MisbehavingVerifierMock")).deploy();
          await rotateTo(hostile); // installed through the delayed path while it had no halt surface
        });

        const programAll = async (behavior: number) => {
          for (const s of Object.values(SEL)) await hostile.program(s, behavior, ethers.ZeroHash);
        };

        for (const [label, program] of [
          [
            "claims the consumer's owner as its halt principal",
            async () => hostile.program(SEL.HALT_PRINCIPAL, B.ReturnOwner, ethers.ZeroHash),
          ],
          ["burns all the gas each probe gets", async () => programAll(B.BurnGas)],
          ["returns a mebibyte to each probe", async () => programAll(B.ReturnHuge)],
          [
            "reverts with the owner's address as its revert data",
            async () => hostile.program(SEL.HALT_PRINCIPAL, B.RevertWithWord, word(admin.address)),
          ],
        ] as const) {
          it(`${c.name}: a current verifier that ${label} cannot stop the owner rotating away from it`, async function () {
            await program();
            await consumer.connect(admin).proposePQVerifier(await w2.getAddress());
            await networkHelpers.time.increase(ROTATION_DELAY);
            await consumer.connect(admin).applyPQVerifierUpdate({ gasLimit: 2_000_000n });
            expect(await consumer.pqVerifier()).to.equal(await w2.getAddress());
          });
        }

        it(`${c.name}: a current verifier can only delay an ownership transfer (rotating away from it ends the veto)`, async function () {
          await hostile.program(SEL.HALT_PRINCIPAL, B.ReturnPendingOwner, ethers.ZeroHash);
          await consumer.connect(admin).transferOwnership(successor.address);
          await expect(consumer.connect(successor).acceptOwnership()).to.be.revertedWithCustomError(
            consumer,
            "HaltPrincipalCannotGovern",
          );
          await rotateTo(w2);
          await consumer.connect(successor).acceptOwnership();
          expect(await consumer.owner()).to.equal(successor.address);
        });

        it(`${c.name}: the documented residual: an installed verifier can make the consumer record one identity as halted, never every identity`, async function () {
          await hostile.program(SEL.halted, B.Return, word("0x01"));
          await hostile.program(SEL.SP1_VERIFIER, B.Return, word(await sp1.getAddress()));
          await hostile.program(SEL.PROGRAM_VKEY, B.Return, VKEY_A);
          await rotateTo(w2); // leaving a verifier that claims to be a halted wrapper of identity A
          const claimed = await identityOf(w1); // w1 is identity A
          expect(await consumer.haltedVerifierIdentities(claimed)).to.equal(true);
          const freshA = await deployWrapper(sp1, VKEY_A, otherHaltPrincipal.address);
          await expect(
            consumer.connect(admin).proposePQVerifier(await freshA.getAddress()),
          ).to.be.revertedWithCustomError(consumer, "HaltedVerifierIdentity");
          // Bounded: any other identity is still admissible.
          const otherB = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
          await consumer.connect(admin).proposePQVerifier(await otherB.getAddress());
        });
      });

      describe("a malformed answer reads as no answer (a probe never invents a halt principal, a halt or an identity)", function () {
        let target: any;
        beforeEach(async function () {
          target = await (await ethers.getContractFactory("MisbehavingVerifierMock")).deploy();
        });
        const dirty = (address: string) => ethers.toBeHex(BigInt(address) | (1n << 200n), 32);
        const proposeTarget = async () => consumer.connect(admin).proposePQVerifier(await target.getAddress());

        it(`${c.name}: positive control: a well-formed halt principal naming the owner is refused`, async function () {
          await target.program(SEL.HALT_PRINCIPAL, B.Return, word(admin.address));
          await expect(proposeTarget()).to.be.revertedWithCustomError(consumer, "HaltPrincipalCannotGovern");
        });

        it(`${c.name}: a halt principal word with dirty upper bits, or a failed call carrying the owner's address, names no one`, async function () {
          await target.program(SEL.HALT_PRINCIPAL, B.Return, dirty(admin.address));
          await proposeTarget();
          await target.program(SEL.HALT_PRINCIPAL, B.RevertWithWord, word(admin.address));
          await proposeTarget();
          expect(await consumer.pendingPQVerifier()).to.equal(await target.getAddress());
        });

        it(`${c.name}: positive control: a well-formed halted() is refused; a one-byte answer, or a failed call carrying 1, is not a halt`, async function () {
          await target.program(SEL.halted, B.Return, word("0x01"));
          await expect(proposeTarget()).to.be.revertedWithCustomError(consumer, "HaltedVerifierTarget");
          await target.program(SEL.halted, B.ReturnShort, ethers.toBeHex(1n << 248n, 32));
          await proposeTarget();
          await target.program(SEL.halted, B.RevertWithWord, word("0x01"));
          await proposeTarget();
        });

        it(`${c.name}: an identity needs two well-formed answers: a dirty, failed or missing half is no identity`, async function () {
          await w1.connect(haltPrincipal).halt();
          const sp1Word = word(await sp1.getAddress());
          // Positive control: two well-formed halves naming identity A are refused while A is halted.
          await target.program(SEL.SP1_VERIFIER, B.Return, sp1Word);
          await target.program(SEL.PROGRAM_VKEY, B.Return, VKEY_A);
          await expect(proposeTarget()).to.be.revertedWithCustomError(consumer, "HaltedVerifierIdentity");
          for (const [sp1Answer, vkeyAnswer] of [
            [
              [B.Return, dirty(await sp1.getAddress())],
              [B.Return, VKEY_A],
            ],
            [
              [B.RevertWithWord, sp1Word],
              [B.Return, VKEY_A],
            ],
            [
              [B.Return, sp1Word],
              [B.RevertWithWord, VKEY_A],
            ],
            [
              [B.Return, sp1Word],
              [B.Revert, ethers.ZeroHash],
            ],
          ] as const) {
            await target.program(SEL.SP1_VERIFIER, sp1Answer[0], sp1Answer[1]);
            await target.program(SEL.PROGRAM_VKEY, vkeyAnswer[0], vkeyAnswer[1]);
            await proposeTarget();
          }
        });
      });
    });
  }
});

describe("SP1-TD2 multisig verifier rotation (TD2-MULTISIG-ROTATION)", function () {
  let admin: any, haltPrincipal: any, tenant: any, recipient: any, attacker: any, otherHaltPrincipal: any;
  let signerA: any, signerB: any, signerC: any;
  let sp1: any, w1: any, w2: any, multisig: any;
  let keys: MlDsaKey[];

  const TYPES = {
    MultiSigWithdrawal: [
      { name: "vaultOwner", type: "address" },
      { name: "recipient", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  const ascending = (signers: any[]) => [...signers].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));

  beforeEach(async function () {
    [admin, haltPrincipal, tenant, recipient, attacker, otherHaltPrincipal, signerA, signerB, signerC] =
      await ethers.getSigners();
    sp1 = await deploySp1();
    w1 = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
    w2 = await deployWrapper(sp1, VKEY_B, otherHaltPrincipal.address);
    multisig = await (await ethers.getContractFactory("WalletWallMultiSigVault", admin)).deploy(await w1.getAddress());
    keys = [mlDsaKey(), mlDsaKey(), mlDsaKey()];
    // A tenant vault: 2-of-3 ECDSA and 2-of-3 ML-DSA-65.
    await multisig.connect(tenant).createVault(
      ascending([signerA, signerB, signerC]).map((s) => s.address),
      2,
      keys.map((k) => k.publicKey),
      2,
    );
    await multisig.connect(tenant).deposit({ value: ethers.parseEther("10") });
  });

  /** A signed withdrawal: the request, its digest, the ECDSA quorum's signatures and ML-DSA signatures by keys 0 and 2. */
  async function authorization(amount: bigint, deadlineOffset = 30 * 86400) {
    const request = {
      vaultOwner: tenant.address,
      recipient: recipient.address,
      amount,
      nonce: (await multisig.getVault(tenant.address)).nonce,
      deadline: BigInt(await networkHelpers.time.latest()) + BigInt(deadlineOffset),
    };
    const domain = {
      name: "WalletWallMultiSigVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await multisig.getAddress(),
    };
    const digest = ethers.TypedDataEncoder.hash(domain, TYPES, request);
    const ecdsa = await Promise.all(ascending([signerA, signerB]).map((s) => s.signTypedData(domain, TYPES, request)));
    const mlDsa = [mlDsaSign(digest, keys[0]), mlDsaSign(digest, keys[2])];
    return { request, digest, ecdsa, mlDsa };
  }

  /** The PQ signatures for `wrapper`: the same ML-DSA-65 signatures, each wrapped in a proof for that wrapper. */
  const proofsFor = async (wrapper: any, auth: Awaited<ReturnType<typeof authorization>>) => [
    await proveFor(wrapper, auth.digest, keys[0].publicKey, auth.mlDsa[0]),
    await proveFor(wrapper, auth.digest, keys[2].publicKey, auth.mlDsa[1]),
  ];

  describe("the delayed path mirrors WalletWallVault's rotation", function () {
    it("the delay and the apply window are the repository's (172,800 s and 14 days, WalletWallVault's constants)", async function () {
      const vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await w1.getAddress());
      expect(await multisig.PQ_VERIFIER_UPDATE_DELAY()).to.equal(BigInt(ROTATION_DELAY));
      expect(await multisig.PQ_VERIFIER_UPDATE_DELAY()).to.equal(await vault.PQ_VERIFIER_UPDATE_DELAY());
      expect(await multisig.GOVERNANCE_GRACE_PERIOD()).to.equal(BigInt(GRACE_PERIOD));
      expect(await multisig.GOVERNANCE_GRACE_PERIOD()).to.equal(await vault.GOVERNANCE_GRACE_PERIOD());
    });

    it("propose emits, apply waits the full delay, and the proposal clears on apply", async function () {
      const tx = multisig.connect(admin).proposePQVerifier(await w2.getAddress());
      await expect(tx).to.emit(multisig, "PQVerifierUpdateProposed");
      const validAfter = await multisig.pendingPQVerifierValidAfter();
      expect(validAfter).to.equal(BigInt(await networkHelpers.time.latest()) + BigInt(ROTATION_DELAY));
      await networkHelpers.time.setNextBlockTimestamp(validAfter - 1n);
      await expect(multisig.connect(admin).applyPQVerifierUpdate())
        .to.be.revertedWithCustomError(multisig, "PQVerifierUpdateNotReady")
        .withArgs(validAfter, validAfter - 1n);
      await networkHelpers.time.setNextBlockTimestamp(validAfter);
      await expect(multisig.connect(admin).applyPQVerifierUpdate())
        .to.emit(multisig, "PQVerifierUpdated")
        .withArgs(await w1.getAddress(), await w2.getAddress());
      expect(await multisig.pqVerifier()).to.equal(await w2.getAddress());
      expect(await multisig.pendingPQVerifier()).to.equal(ethers.ZeroAddress);
      expect(await multisig.pendingPQVerifierValidAfter()).to.equal(0n);
    });

    it("refuses a zero or code-less target, an empty apply or cancel, and a target that lost its code during the delay", async function () {
      await expect(multisig.connect(admin).proposePQVerifier(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        multisig,
        "ZeroAddress",
      );
      await expect(multisig.connect(admin).proposePQVerifier(attacker.address))
        .to.be.revertedWithCustomError(multisig, "NoCode")
        .withArgs(attacker.address);
      for (const fn of ["applyPQVerifierUpdate", "cancelPQVerifierUpdate"]) {
        await expect(multisig.connect(admin).getFunction(fn)()).to.be.revertedWithCustomError(
          multisig,
          "NoPendingPQVerifier",
        );
      }
      await multisig.connect(admin).proposePQVerifier(await w2.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await networkHelpers.setCode(await w2.getAddress(), "0x");
      await expect(multisig.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(multisig, "NoCode");
      expect(await multisig.pqVerifier()).to.equal(await w1.getAddress());
      expect(await multisig.pendingPQVerifier(), "a rejected apply leaves the proposal cancellable").to.equal(
        await w2.getAddress(),
      );
      await expect(multisig.connect(admin).cancelPQVerifierUpdate())
        .to.emit(multisig, "PQVerifierUpdateCancelled")
        .withArgs(await w2.getAddress());
    });

    it("a re-proposal restarts the delay, and a matured proposal expires after the apply window", async function () {
      await multisig.connect(admin).proposePQVerifier(await w2.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY - 10);
      await multisig.connect(admin).proposePQVerifier(await w2.getAddress());
      await networkHelpers.time.increase(20);
      await expect(multisig.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        multisig,
        "PQVerifierUpdateNotReady",
      );
      const validAfter = await multisig.pendingPQVerifierValidAfter();
      await networkHelpers.time.setNextBlockTimestamp(validAfter + BigInt(GRACE_PERIOD) + 1n);
      await expect(multisig.connect(admin).applyPQVerifierUpdate())
        .to.be.revertedWithCustomError(multisig, "ProposalExpired")
        .withArgs(validAfter, validAfter + BigInt(GRACE_PERIOD), validAfter + BigInt(GRACE_PERIOD) + 1n);
      // Positive control: at the last instant of the window it applies.
      await multisig.connect(admin).proposePQVerifier(await w2.getAddress());
      const again = await multisig.pendingPQVerifierValidAfter();
      await networkHelpers.time.setNextBlockTimestamp(again + BigInt(GRACE_PERIOD));
      await multisig.connect(admin).applyPQVerifierUpdate();
      expect(await multisig.pqVerifier()).to.equal(await w2.getAddress());
    });
  });

  describe("HALTED_THEN_ROTATED_WITHDRAWAL_SUCCEEDS", function () {
    it("halted, the multisig cannot withdraw through the old wrapper; after the delay and a rotation to a fresh valid wrapper the same authorization succeeds", async function () {
      // Positive control: a withdrawal through the ACTIVE wrapper pays.
      const first = await authorization(ethers.parseEther("1"));
      await expect(multisig.withdraw(first.request, first.ecdsa, await proofsFor(w1, first), [0, 2])).to.emit(
        multisig,
        "Withdrawn",
      );

      // The authorization under test: valid now, through the ACTIVE wrapper.
      const auth = await authorization(ethers.parseEther("2"));
      const viaW1 = await proofsFor(w1, auth);
      await multisig.withdraw.staticCall(auth.request, auth.ecdsa, viaW1, [0, 2]);

      await w1.connect(haltPrincipal).halt();
      await expect(multisig.withdraw(auth.request, auth.ecdsa, viaW1, [0, 2])).to.be.revertedWithCustomError(
        multisig,
        "InvalidSignature",
      );
      // A proof for any other wrapper is refused too while w1 is installed: it commits another verifier address.
      await expect(
        multisig.withdraw(auth.request, auth.ecdsa, await proofsFor(w2, auth), [0, 2]),
      ).to.be.revertedWithCustomError(multisig, "InvalidSignature");

      await multisig.connect(admin).proposePQVerifier(await w2.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await multisig.connect(admin).applyPQVerifierUpdate();

      // The same request, the same ECDSA signatures and the same ML-DSA-65 signatures; only the proof wrapping
      // differs, because a proof commits the wrapper it was made for.
      const before = (await multisig.getVault(tenant.address)).balance;
      await expect(multisig.withdraw(auth.request, auth.ecdsa, await proofsFor(w2, auth), [0, 2]))
        .to.emit(multisig, "Withdrawn")
        .withArgs(tenant.address, recipient.address, auth.request.amount, auth.request.nonce);
      expect((await multisig.getVault(tenant.address)).balance).to.equal(before - auth.request.amount);
      expect(await w1.halted(), "the old wrapper is still HALTED").to.equal(true);
    });
  });

  describe("MALICIOUS_REPLACEMENT_BLOCKED_OUTSIDE_DELAYED_PATH", function () {
    let acceptAll: any;
    beforeEach(async function () {
      acceptAll = await (await ethers.getContractFactory("AlwaysTruePQCVerifier")).deploy();
    });

    /** A forged withdrawal: the tenant's real ECDSA quorum, PQ "signatures" nobody made. */
    const forged = async () => {
      const auth = await authorization(ethers.parseEther("5"));
      const junk = [ethers.hexlify(ethers.randomBytes(64)), ethers.hexlify(ethers.randomBytes(64))];
      return { auth, junk };
    };

    it("an accept-all replacement is not active at any instant before the full delay, even though the owner proposed it", async function () {
      const { auth, junk } = await forged();
      await multisig.connect(admin).proposePQVerifier(await acceptAll.getAddress());
      const validAfter = await multisig.pendingPQVerifierValidAfter();
      await expect(multisig.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        multisig,
        "PQVerifierUpdateNotReady",
      );
      await networkHelpers.time.setNextBlockTimestamp(validAfter - 1n);
      await expect(multisig.connect(admin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        multisig,
        "PQVerifierUpdateNotReady",
      );
      expect(await multisig.pqVerifier()).to.equal(await w1.getAddress());
      await expect(multisig.withdraw(auth.request, auth.ecdsa, junk, [0, 2])).to.be.revertedWithCustomError(
        multisig,
        "InvalidSignature",
      );
    });

    it("nobody but the owner can propose, apply or cancel: not a tenant, its signers, an attacker or the halt principal", async function () {
      for (const who of [tenant, signerA, attacker, haltPrincipal]) {
        await expect(
          multisig.connect(who).proposePQVerifier(await acceptAll.getAddress()),
        ).to.be.revertedWithCustomError(multisig, "OwnableUnauthorizedAccount");
      }
      await multisig.connect(admin).proposePQVerifier(await acceptAll.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      for (const who of [tenant, signerA, attacker, haltPrincipal]) {
        for (const fn of ["applyPQVerifierUpdate", "cancelPQVerifierUpdate"]) {
          await expect(multisig.connect(who).getFunction(fn)()).to.be.revertedWithCustomError(
            multisig,
            "OwnableUnauthorizedAccount",
          );
        }
      }
      expect(await multisig.pqVerifier()).to.equal(await w1.getAddress());
    });

    it("no other function installs a verifier: every state-changing function, from every principal, leaves pqVerifier alone", async function () {
      const defaults = (param: any, caller: string): unknown => {
        if (param.baseType === "array") return [];
        if (param.baseType === "tuple") return (param.components ?? []).map((p: any) => defaults(p, caller));
        if (param.baseType === "address") return caller === "verifier" ? acceptAll.target : caller;
        if (param.baseType.startsWith("uint") || param.baseType.startsWith("int")) return 1n;
        if (param.baseType === "bool") return false;
        if (param.baseType === "bytes32") return ethers.ZeroHash;
        return "0x";
      };
      const names = mutatingFunctions(multisig);
      expect(names.length, "the probe covers the state-changing surface").to.be.greaterThan(8);
      for (const who of [admin, tenant, attacker, haltPrincipal]) {
        for (const name of names) {
          if (name === "proposePQVerifier" || name === "applyPQVerifierUpdate") continue; // the delayed path itself
          const fragment = multisig.interface.getFunction(name)!;
          for (const addressArg of [who.address, "verifier"]) {
            const args = fragment.inputs.map((p: any) => defaults(p, addressArg));
            try {
              await (
                await who.sendTransaction({
                  to: await multisig.getAddress(),
                  data: multisig.interface.encodeFunctionData(fragment, args),
                  value: fragment.payable ? 1n : 0n,
                  gasLimit: 3_000_000n,
                })
              ).wait();
            } catch {
              // Reverting is fine; the property is about state.
            }
            expect(await multisig.pqVerifier(), `${name} from ${who.address}`).to.equal(await w1.getAddress());
          }
        }
      }
    });

    it("the source assigns pqVerifier only in the constructor and in applyPQVerifierUpdate", function () {
      const contract = findContract(loadSourceAst("contracts/WalletWallMultiSigVault.sol"), "WalletWallMultiSigVault");
      const stateVar = (contract.nodes as AstNode[]).find(
        (n) => n.nodeType === "VariableDeclaration" && n.name === "pqVerifier" && n.stateVariable === true,
      )!;
      const writers = new Set<string>();
      for (const fn of contract.nodes as AstNode[]) {
        if (fn.nodeType !== "FunctionDefinition" && fn.nodeType !== "ModifierDefinition") continue;
        walkAst(fn, (node) => {
          const target =
            node.nodeType === "Assignment"
              ? (node.leftHandSide as AstNode)
              : node.nodeType === "UnaryOperation" && node.operator === "delete"
                ? (node.subExpression as AstNode)
                : undefined;
          if (target?.nodeType === "Identifier" && target.referencedDeclaration === stateVar.id) {
            writers.add(fn.kind === "constructor" ? "constructor" : String(fn.name));
          }
        });
      }
      expect([...writers].sort()).to.deep.equal(["applyPQVerifierUpdate", "constructor"]);
    });

    it("the cut, executed: through the full delay the owner CAN install an accept-all verifier, which voids every tenant's PQ factor but not its ECDSA quorum", async function () {
      // This is the new authorization the rotation gives the multisig owner
      // (NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL), shown rather than asserted away.
      const { auth, junk } = await forged();
      await multisig.connect(admin).proposePQVerifier(await acceptAll.getAddress());
      await networkHelpers.time.increase(ROTATION_DELAY);
      await multisig.connect(admin).applyPQVerifierUpdate();
      await expect(multisig.withdraw(auth.request, auth.ecdsa, junk, [0, 2])).to.emit(multisig, "Withdrawn");
      // The tenant's m-of-n ECDSA quorum still binds: one signature short, the forged withdrawal fails.
      const next = await authorization(ethers.parseEther("1"));
      await expect(multisig.withdraw(next.request, [next.ecdsa[0]], junk, [0, 2])).to.be.revertedWithCustomError(
        multisig,
        "InsufficientSignatures",
      );
    });
  });
});
