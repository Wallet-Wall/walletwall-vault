/**
 * Executable evidence for docs/BASE_MAINNET_CUSTODY_ADJUDICATION.md section 4.
 *
 * RESEARCH PROTOTYPE — NOT AUDITED — TESTNET / LOCAL ONLY. These tests prove properties of the
 * CURRENT shared-ledger contracts (Architecture A) on a local Hardhat network with a mock
 * token. They deploy nothing, touch no network, and authorise nothing for real value.
 *
 * Each attack is paired with a POSITIVE CONTROL in the same test, so a vacuous revert (a
 * harness fault, a malformed signature) can never pass as evidence of the property claimed.
 *
 * Subject: StablecoinVaultSimulator, the ERC-20 sibling of WalletWallVault and the closest
 * existing analogue of a USDC vault. The four facts pinned here are the ones the adjudication
 * rejects Architecture A on:
 *
 *   E-1  the contract admin's pause freezes EVERY tenant's spend and recovery execution, with
 *        no bound, while every tenant's tokens stay pooled at the contract address;
 *   E-2  a WalletWall-operated attestor ALONE moves a PqOnly tenant's tokens — the tenant signs
 *        nothing — while a Hybrid tenant is protected only by the ECDSA conjunct;
 *   E-3  lifecycle entrypoints are keyed on msg.sender, so a gas-paying relayer cannot act for
 *        a sponsored user, while withdraw/queueWithdrawal ARE relayable;
 *   E-4  all tenants share one token balance at one address; a direct transfer is credited to
 *        nobody and no entrypoint exists that could move it.
 */

import { expect } from "chai";
import { FunctionFragment } from "ethers";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { AttestationPQCVerifier, MockMLDSAVerifier, MockUSDC, StablecoinVaultSimulator } from "../typechain-types";
import { WITHDRAWAL_TYPES, buildAttestationPayload, simulatorDomain } from "./helpers/simulatorHelpers";

const VaultMode = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;
const MUSDC = (n: number) => BigInt(n) * 1_000_000n;

const DEPOSIT = MUSDC(500);
const SPEND = MUSDC(100);
const LARGE = MUSDC(300);
const THRESHOLD = MUSDC(200);
const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
const RECOVERY_DELAY = 7 * 24 * 60 * 60;
const LARGE_TX_DELAY = 3 * 24 * 60 * 60;
const ONE_YEAR = 365 * 24 * 60 * 60;

// Mock-verifier PQ material: the mock checks lengths and a non-zero signature prefix only.
const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
const mockPqSig = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

interface Withdrawal {
  vaultOwner: string;
  recipient: string;
  amount: bigint;
  nonce: number;
  deadline: number;
  vaultMode: number;
}

describe("Base Mainnet custody adjudication — executable evidence against the shared-ledger contracts", function () {
  let admin: HardhatEthersSigner;
  let tenantA: HardhatEthersSigner;
  let tenantB: HardhatEthersSigner;
  let relayer: HardhatEthersSigner;
  let attestor: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let newSigner: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;
  let stranger: HardhatEthersSigner;

  let token: MockUSDC;
  let mockVerifier: MockMLDSAVerifier;
  let sim: StablecoinVaultSimulator;

  async function request(
    sim_: StablecoinVaultSimulator,
    owner: HardhatEthersSigner,
    mode: number,
    overrides: Partial<Withdrawal> = {},
  ) {
    const nonce = Number((await sim_.getVault(owner.address)).nonce);
    return {
      vaultOwner: owner.address,
      recipient: recipient.address,
      amount: SPEND,
      nonce,
      deadline: (await networkHelpers.time.latest()) + 3600,
      vaultMode: mode,
      ...overrides,
    } as Withdrawal;
  }

  async function ecdsaSign(sim_: StablecoinVaultSimulator, signer: HardhatEthersSigner, req: Withdrawal) {
    return signer.signTypedData(await simulatorDomain(sim_), WITHDRAWAL_TYPES, req);
  }

  async function fund(
    sim_: StablecoinVaultSimulator,
    tenant: HardhatEthersSigner,
    mode: number,
    signer = tenant.address,
  ) {
    await sim_.connect(tenant).createVault(signer, PQ_KEY, mode);
    await token.connect(tenant).mint(tenant.address, DEPOSIT);
    await token.connect(tenant).approve(await sim_.getAddress(), DEPOSIT);
    await sim_.connect(tenant).deposit(DEPOSIT);
  }

  beforeEach(async function () {
    [admin, tenantA, tenantB, relayer, attestor, recipient, newSigner, guardian1, guardian2, guardian3, stranger] =
      await ethers.getSigners();

    token = await (await ethers.getContractFactory("MockUSDC")).deploy();
    await token.waitForDeployment();
    mockVerifier = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
    await mockVerifier.waitForDeployment();
    sim = await (
      await ethers.getContractFactory("StablecoinVaultSimulator", admin)
    ).deploy(await token.getAddress(), await mockVerifier.getAddress());
    await sim.waitForDeployment();
  });

  it("E-1: the admin's pause freezes every tenant's spend and recovery execution with no bound; tokens stay pooled", async function () {
    await fund(sim, tenantA, VaultMode.Hybrid);
    await fund(sim, tenantB, VaultMode.Hybrid);

    // Tenant B has a fully supported, matured recovery waiting to execute.
    await sim.connect(tenantB).setGuardians([guardian1.address, guardian2.address, guardian3.address]);
    await sim.connect(guardian1).initiateRecovery(tenantB.address, newSigner.address, PQ_KEY);
    await sim.connect(guardian1).supportRecovery(tenantB.address);
    await sim.connect(guardian2).supportRecovery(tenantB.address);
    await networkHelpers.time.increase(RECOVERY_DELAY);

    const pooledBefore = await token.balanceOf(await sim.getAddress());
    expect(pooledBefore).to.equal(DEPOSIT * 2n);

    await sim.connect(admin).pause();

    // Every tenant's spend is refused, and so is the matured recovery.
    const reqA = await request(sim, tenantA, VaultMode.Hybrid);
    await expect(
      sim.connect(relayer).withdraw(reqA, await ecdsaSign(sim, tenantA, reqA), mockPqSig()),
    ).to.be.revertedWithCustomError(sim, "EnforcedPause");
    await expect(sim.connect(stranger).executeRecovery(tenantB.address)).to.be.revertedWithCustomError(
      sim,
      "EnforcedPause",
    );

    // A year later nothing has lifted: the freeze has no expiry, budget, or second principal.
    await networkHelpers.time.increase(ONE_YEAR);
    const reqA2 = await request(sim, tenantA, VaultMode.Hybrid);
    await expect(
      sim.connect(relayer).withdraw(reqA2, await ecdsaSign(sim, tenantA, reqA2), mockPqSig()),
    ).to.be.revertedWithCustomError(sim, "EnforcedPause");
    await expect(sim.connect(stranger).executeRecovery(tenantB.address)).to.be.revertedWithCustomError(
      sim,
      "EnforcedPause",
    );
    expect(await token.balanceOf(await sim.getAddress())).to.equal(pooledBefore);

    // POSITIVE CONTROL: the same payloads succeed the moment the single admin principal unpauses.
    await sim.connect(admin).unpause();
    const reqA3 = await request(sim, tenantA, VaultMode.Hybrid);
    await expect(sim.connect(relayer).withdraw(reqA3, await ecdsaSign(sim, tenantA, reqA3), mockPqSig())).to.emit(
      sim,
      "Withdrawn",
    );
    await expect(sim.connect(stranger).executeRecovery(tenantB.address)).to.emit(sim, "RecoveryExecuted");
  });

  it("E-2: the attestor alone moves a PqOnly tenant's tokens with no tenant signature; Hybrid is protected only by ECDSA", async function () {
    const attestationVerifier: AttestationPQCVerifier = await (
      await ethers.getContractFactory("AttestationPQCVerifier", admin)
    ).deploy(attestor.address);
    await attestationVerifier.waitForDeployment();
    const attested = await (
      await ethers.getContractFactory("StablecoinVaultSimulator", admin)
    ).deploy(await token.getAddress(), await attestationVerifier.getAddress());
    await attested.waitForDeployment();

    // PqOnly is admitted because the verifier is not the mock. The tenant's ECDSA signer is unset by design.
    await fund(attested, tenantA, VaultMode.PqOnly, ethers.ZeroAddress);
    await fund(attested, tenantB, VaultMode.Hybrid);

    // The attestor (WalletWall infrastructure) chooses the recipient and attests to the digest. Nobody else signs.
    const stolen = await request(attested, tenantA, VaultMode.PqOnly, { recipient: stranger.address });
    const digest = ethers.TypedDataEncoder.hash(await simulatorDomain(attested), WITHDRAWAL_TYPES, stolen);
    const attestation = await buildAttestationPayload(await attestationVerifier.getAddress(), attestor, digest, PQ_KEY);

    const before = await token.balanceOf(stranger.address);
    await expect(attested.connect(relayer).withdraw(stolen, "0x", attestation)).to.emit(attested, "Withdrawn");
    expect(await token.balanceOf(stranger.address)).to.equal(before + SPEND);
    expect((await attested.getVault(tenantA.address)).balance).to.equal(DEPOSIT - SPEND);

    // POSITIVE CONTROL: against a Hybrid tenant the identical attestor-authorised payload is refused,
    // because the ECDSA conjunct is still required — the attestor's authority is mode-dependent, not absent.
    const hybrid = await request(attested, tenantB, VaultMode.Hybrid, { recipient: stranger.address });
    const hybridDigest = ethers.TypedDataEncoder.hash(await simulatorDomain(attested), WITHDRAWAL_TYPES, hybrid);
    const hybridAttestation = await buildAttestationPayload(
      await attestationVerifier.getAddress(),
      attestor,
      hybridDigest,
      PQ_KEY,
    );
    await expect(
      attested.connect(relayer).withdraw(hybrid, await ecdsaSign(attested, stranger, hybrid), hybridAttestation),
    ).to.be.revertedWithCustomError(attested, "InvalidEcdsaSignature");
    await expect(
      attested.connect(relayer).withdraw(hybrid, await ecdsaSign(attested, tenantB, hybrid), hybridAttestation),
    ).to.emit(attested, "Withdrawn");
  });

  it("E-3: lifecycle entrypoints are keyed on msg.sender, so a relayer cannot act for a sponsored user; withdraw and queueWithdrawal relay", async function () {
    await fund(sim, tenantA, VaultMode.Hybrid);

    // Guardian administration names no vault owner: the relayer can only administer its own (non-existent) vault.
    await expect(
      sim.connect(relayer).setGuardians([guardian1.address, guardian2.address, guardian3.address]),
    ).to.be.revertedWithCustomError(sim, "VaultDoesNotExist");
    await expect(sim.connect(relayer).cancelRecovery()).to.be.revertedWithCustomError(sim, "RecoveryDoesNotExist");
    await expect(sim.connect(relayer).setTreasuryQuorumThreshold(1)).to.be.revertedWithCustomError(
      sim,
      "VaultDoesNotExist",
    );

    // Vault creation is keyed on the caller: a relayer creating "for" a sponsored user creates the RELAYER's vault.
    expect((await sim.getVault(stranger.address)).exists).to.equal(false);
    await sim.connect(relayer).createVault(stranger.address, PQ_KEY, VaultMode.Hybrid);
    expect((await sim.getVault(stranger.address)).exists).to.equal(false);
    expect((await sim.getVault(relayer.address)).exists).to.equal(true);

    // Queue/finalize: queueing is relayable, finalization and cancellation are not.
    await sim.connect(admin).proposeLargeTxParams(THRESHOLD, LARGE_TX_DELAY);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await sim.connect(admin).applyLargeTxParams();

    const large = await request(sim, tenantA, VaultMode.Hybrid, { amount: LARGE });
    await expect(
      sim.connect(relayer).queueWithdrawal(large, await ecdsaSign(sim, tenantA, large), mockPqSig()),
    ).to.emit(sim, "WithdrawalQueued");
    const operationId = await sim.hashWithdrawal(large);
    await networkHelpers.time.increase(LARGE_TX_DELAY);

    await expect(sim.connect(relayer).finalizeWithdrawal(tenantA.address, operationId)).to.be.revertedWithCustomError(
      sim,
      "NotPendingWithdrawalOwner",
    );
    await expect(sim.connect(relayer).cancelPendingWithdrawal(operationId)).to.be.revertedWithCustomError(
      sim,
      "NoPendingWithdrawal",
    );

    // POSITIVE CONTROLS: the tenant can finalize with its own gas, and an ordinary withdrawal is relayable.
    await expect(sim.connect(tenantA).finalizeWithdrawal(tenantA.address, operationId)).to.emit(
      sim,
      "WithdrawalFinalized",
    );
    const small = await request(sim, tenantA, VaultMode.Hybrid);
    await expect(sim.connect(relayer).withdraw(small, await ecdsaSign(sim, tenantA, small), mockPqSig())).to.emit(
      sim,
      "Withdrawn",
    );
  });

  it("E-4: every tenant's tokens sit in one pooled balance; a direct transfer is credited to nobody and nothing can move it", async function () {
    await fund(sim, tenantA, VaultMode.Hybrid);
    await fund(sim, tenantB, VaultMode.Hybrid);
    const simAddress = await sim.getAddress();

    const accounted = async () =>
      (await sim.getVault(tenantA.address)).balance + (await sim.getVault(tenantB.address)).balance;
    expect(await token.balanceOf(simAddress)).to.equal(await accounted());

    // A direct ERC-20 transfer lands in the pool but credits no vault record.
    const stray = MUSDC(50);
    await token.connect(stranger).mint(stranger.address, stray);
    await token.connect(stranger).transfer(simAddress, stray);
    expect(await token.balanceOf(simAddress)).to.equal((await accounted()) + stray);

    // No entrypoint exists that could move it: the ABI carries no sweep/rescue/token-recovery selector (the
    // credential-recovery functions are about keys, not tokens), and the only token-moving paths
    // (withdraw, finalizeWithdrawal) debit an accounted balance first.
    const suspicious = sim.interface.fragments
      .filter((f): f is FunctionFragment => f.type === "function")
      .map((f) => f.name)
      .filter((name) =>
        /sweep|rescue|skim|recoverERC20|recoverToken|emergencyWithdraw|adminWithdraw|withdrawToken|transferToken/i.test(
          name,
        ),
      );
    expect(suspicious).to.deep.equal([]);

    // POSITIVE CONTROL: accounted balances remain spendable and exact, so the stray amount is provably the only orphan.
    const reqA = await request(sim, tenantA, VaultMode.Hybrid, { amount: DEPOSIT });
    await expect(sim.connect(relayer).withdraw(reqA, await ecdsaSign(sim, tenantA, reqA), mockPqSig())).to.emit(
      sim,
      "Withdrawn",
    );
    const reqB = await request(sim, tenantB, VaultMode.Hybrid, { amount: DEPOSIT });
    await expect(sim.connect(relayer).withdraw(reqB, await ecdsaSign(sim, tenantB, reqB), mockPqSig())).to.emit(
      sim,
      "Withdrawn",
    );
    expect(await accounted()).to.equal(0n);
    expect(await token.balanceOf(simAddress)).to.equal(stray);
  });
});
