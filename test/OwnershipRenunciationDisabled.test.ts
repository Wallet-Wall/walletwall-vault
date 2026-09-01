/**
 * T0 regression — unsafe ownership renunciation must be impossible.
 *
 * THE DEFECT THIS PINS
 * --------------------
 * `pause()` and `unpause()` are `onlyOwner` on both production vaults.
 * `renounceOwnership()` is inherited from OpenZeppelin `Ownable` as
 * `public virtual onlyOwner`, and `Ownable2Step` overrides `pendingOwner`,
 * `transferOwnership`, `_transferOwnership` and `acceptOwnership` — but NOT
 * `renounceOwnership`. Before this lane neither vault overrode it either, so it
 * was reachable in both compiled ABIs.
 *
 * That made this sequence available to a single principal, in two transactions,
 * with no delay, no quorum and no expiry:
 *
 *     pause()               -> withdraw / queue / finalize / rotate /
 *                              initiateRecovery / executeRecovery all stop
 *     renounceOwnership()   -> owner() becomes address(0)
 *                           -> unpause() is uncallable by anyone, forever
 *
 * The result is a permanent, irreversible, cross-tenant freeze of withdrawal AND
 * of recovery execution. It is the only hazard in the register with no recovery
 * path of any kind.
 *
 * WHAT THIS SUITE PROVES, AND WHAT IT DOES NOT
 * --------------------------------------------
 * It proves that on the REAL production contracts the renunciation transition is
 * unreachable, that the surrounding ownership and pause semantics are unchanged,
 * and — via `RenounceableOwnableMutant` — that the discriminator would FAIL if
 * renunciation were ever restored. The permanence itself is demonstrated by
 * exercising real state on the mutant, not asserted by a fixture.
 *
 * It does NOT claim the pause surface is otherwise safe, and it deliberately does
 * not change it. The one-sided `deposit()` divergence recorded below is evidence
 * only; closing it is a separate lane.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import { findContract, findFunctionDefinition, loadSourceAst } from "./helpers/solidityAst";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import type { MockMLDSAVerifier, MockUSDC, StablecoinVaultSimulator, WalletWallVault } from "../typechain-types";

const ZERO = "0x0000000000000000000000000000000000000000";

interface AstStatement {
  nodeType?: string;
  expression?: {
    nodeType?: string;
    expression?: { nodeType?: string; memberName?: string; expression?: { name?: string } };
  };
}

/**
 * Whether an AST statement is a coverage probe injected by `solidity-coverage`
 * rather than something an author wrote.
 *
 * The instrumenter rewrites the source to prefix each statement with
 * `__NomicFoundationCoverage.sendHit(0x...)`. Matching on the member name AND the
 * base identifier keeps this from silently discounting a real call that merely
 * happens to be named `sendHit`.
 */
function isCoverageHit(statement: AstStatement): boolean {
  if (statement.nodeType !== "ExpressionStatement") return false;
  const call = statement.expression;
  if (call?.nodeType !== "FunctionCall") return false;
  const callee = call.expression;
  if (callee?.nodeType !== "MemberAccess" || callee.memberName !== "sendHit") return false;
  return (callee.expression?.name ?? "").includes("Coverage");
}

/**
 * Send a transaction and report ONLY whether it reverted, without asserting how.
 * Used where the test must stay agnostic about which error surfaces — the safety
 * property is about state, not about the revert reason.
 */
async function reverts(send: () => Promise<unknown>): Promise<boolean> {
  try {
    const result = await send();
    // A state-changing call returns a tx response to await; a view/pure call
    // returns nothing. The production override is `pure` (so typechain treats it
    // as a call) while the M1 mutant inherits the `nonpayable` version (a
    // transaction), and this helper must handle both without caring which.
    if (result && typeof (result as { wait?: unknown }).wait === "function") {
      await (result as { wait: () => Promise<unknown> }).wait();
    }
    return false;
  } catch {
    return true;
  }
}

describe("ownership renunciation is disabled (T0)", function () {
  let owner: HardhatEthersSigner;
  let successor: HardhatEthersSigner;
  let stranger: HardhatEthersSigner;

  let vault: WalletWallVault;
  let sim: StablecoinVaultSimulator;
  let verifier: MockMLDSAVerifier;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));

  beforeEach(async function () {
    [owner, successor, stranger] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    const Token = await ethers.getContractFactory("MockUSDC");
    const token: MockUSDC = await Token.deploy();
    const Sim = await ethers.getContractFactory("StablecoinVaultSimulator");
    sim = await Sim.deploy(await token.getAddress(), await verifier.getAddress());
  });

  // -------------------------------------------------------------------------
  // The discriminator. This is the assertion the fix exists to satisfy.
  // -------------------------------------------------------------------------

  describe("the renunciation transition is unreachable", function () {
    // The primary state invariant, deliberately written WITHOUT any revert
    // matcher. It does not care how the call fails, only that the owner slot
    // cannot reach address(0). Before the fix this fails by observing the actual
    // post-state — the call SUCCEEDS and zeroes the owner — which is the RED
    // signal the remediation is required to turn green.
    it("WalletWallVault: the owner can never become the zero address", async function () {
      const before = await vault.owner();
      await reverts(() => vault.connect(owner).renounceOwnership());
      expect(await vault.owner(), "renounceOwnership zeroed the owner").to.equal(before);
    });

    it("StablecoinVaultSimulator: the owner can never become the zero address", async function () {
      const before = await sim.owner();
      await reverts(() => sim.connect(owner).renounceOwnership());
      expect(await sim.owner(), "renounceOwnership zeroed the owner").to.equal(before);
    });

    it("WalletWallVault: renounceOwnership reverts and the owner is unchanged", async function () {
      const before = await vault.owner();
      expect(before).to.equal(owner.address);

      await expect(vault.connect(owner).renounceOwnership()).to.be.revertedWithCustomError(
        vault,
        "OwnershipRenunciationDisabled",
      );

      expect(await vault.owner()).to.equal(before);
      expect(await vault.owner()).to.not.equal(ZERO);
    });

    it("StablecoinVaultSimulator: renounceOwnership reverts and the owner is unchanged", async function () {
      const before = await sim.owner();
      expect(before).to.equal(owner.address);

      await expect(sim.connect(owner).renounceOwnership()).to.be.revertedWithCustomError(
        sim,
        "OwnershipRenunciationDisabled",
      );

      expect(await sim.owner()).to.equal(before);
      expect(await sim.owner()).to.not.equal(ZERO);
    });

    it("renunciation is blocked even while paused — the exact hazard sequence", async function () {
      // Step 1 of the hazard: the owner pauses. This still works; pause itself is
      // not the defect and is not changed by this lane.
      await vault.connect(owner).pause();
      expect(await vault.paused()).to.equal(true);

      // Step 2 of the hazard: the owner attempts to strand the pause. Blocked.
      await expect(vault.connect(owner).renounceOwnership()).to.be.revertedWithCustomError(
        vault,
        "OwnershipRenunciationDisabled",
      );

      // The escape therefore survives: the owner still exists and can unpause.
      expect(await vault.owner()).to.equal(owner.address);
      await vault.connect(owner).unpause();
      expect(await vault.paused()).to.equal(false);
    });

    // Deliberately implementation-AGNOSTIC. Whether the disabled function keeps
    // `onlyOwner` (non-owner sees OwnableUnauthorizedAccount) or reverts
    // unconditionally (everyone sees OwnershipRenunciationDisabled) is a design
    // choice about error surface, not about safety. Asserting a specific error
    // here would bake that choice into the test before it was made on merit.
    // What must hold either way: the call fails, and no ownership state moves.
    it("a non-owner also cannot renounce, and gains no ownership-changing path", async function () {
      for (const contract of [vault, sim]) {
        const ownerBefore = await contract.owner();
        const pendingBefore = await contract.pendingOwner();

        const reverted = await reverts(() => contract.connect(stranger).renounceOwnership());

        expect(reverted, "a non-owner call to renounceOwnership must fail").to.equal(true);
        expect(await contract.owner()).to.equal(ownerBefore);
        expect(await contract.pendingOwner()).to.equal(pendingBefore);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Everything the fix must NOT disturb.
  // -------------------------------------------------------------------------

  describe("surrounding ownership semantics are unchanged", function () {
    it("two-step ownership transfer still completes on both contracts", async function () {
      await vault.connect(owner).transferOwnership(successor.address);
      expect(await vault.pendingOwner()).to.equal(successor.address);
      expect(await vault.owner()).to.equal(owner.address); // not yet moved
      await vault.connect(successor).acceptOwnership();
      expect(await vault.owner()).to.equal(successor.address);

      await sim.connect(owner).transferOwnership(successor.address);
      await sim.connect(successor).acceptOwnership();
      expect(await sim.owner()).to.equal(successor.address);
    });

    it("a pending transfer is still not an ownership change until accepted", async function () {
      await vault.connect(owner).transferOwnership(successor.address);
      await expect(vault.connect(successor).pause()).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
      expect(await vault.owner()).to.equal(owner.address);
    });

    it("only the current owner may transfer ownership", async function () {
      await expect(vault.connect(stranger).transferOwnership(stranger.address)).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );
      expect(await vault.pendingOwner()).to.equal(ZERO);
    });

    it("the new owner inherits pause and unpause after a completed transfer", async function () {
      await vault.connect(owner).transferOwnership(successor.address);
      await vault.connect(successor).acceptOwnership();

      await vault.connect(successor).pause();
      expect(await vault.paused()).to.equal(true);
      await vault.connect(successor).unpause();
      expect(await vault.paused()).to.equal(false);

      // and the previous owner has lost it
      await expect(vault.connect(owner).pause()).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
    });
  });

  // -------------------------------------------------------------------------
  // Mutation controls. An assertion that only ever passes proves nothing, so
  // each discriminator above is shown to FAIL against a deliberately broken
  // variant carrying exactly one removed guard.
  // -------------------------------------------------------------------------

  describe("mutation controls", function () {
    it("M1 — with renunciation restored, the freeze is real and PERMANENT (exercised, not asserted)", async function () {
      const Mutant = await ethers.getContractFactory("RenounceableOwnableMutant");
      const mutant = await Mutant.deploy();

      // The guarded operation works while unpaused.
      expect(await mutant.criticalOperation()).to.equal(true);

      // Step 1 — pause.
      await mutant.connect(owner).pause();
      await expect(mutant.criticalOperation()).to.be.revertedWithCustomError(mutant, "EnforcedPause");

      // Step 2 — renounce. On the mutant this SUCCEEDS, exactly as the
      // production contracts did before this lane.
      await mutant.connect(owner).renounceOwnership();
      expect(await mutant.owner()).to.equal(ZERO);

      // The permanence, observed on real state rather than asserted:
      // unpause is now uncallable by the former owner, by a stranger, and by
      // the zero address's would-be successor — there is no caller left.
      for (const who of [owner, successor, stranger]) {
        await expect(mutant.connect(who).unpause()).to.be.revertedWithCustomError(mutant, "OwnableUnauthorizedAccount");
      }

      // And no ownership transition can restore an owner: transferOwnership is
      // itself onlyOwner, so the contract cannot be re-owned.
      await expect(mutant.connect(owner).transferOwnership(successor.address)).to.be.revertedWithCustomError(
        mutant,
        "OwnableUnauthorizedAccount",
      );

      // Terminal state: the guarded operation is unreachable forever.
      await expect(mutant.criticalOperation()).to.be.revertedWithCustomError(mutant, "EnforcedPause");
      expect(await mutant.owner()).to.equal(ZERO);
    });

    it("M1 — the production discriminator would FAIL if renunciation were restored", async function () {
      const Mutant = await ethers.getContractFactory("RenounceableOwnableMutant");
      const mutant = await Mutant.deploy();

      // This is the identical invariant asserted against WalletWallVault above.
      // It must NOT hold here, or it is not discriminating.
      const before = await mutant.owner();
      await reverts(() => mutant.connect(owner).renounceOwnership());
      expect(await mutant.owner(), "the owner-cannot-be-zeroed invariant must FAIL on the mutant").to.not.equal(before);
    });

    it("M4 — an unguarded transferOwnership is caught even though renunciation is blocked", async function () {
      const Mutant = await ethers.getContractFactory("UnguardedTransferMutant");
      const mutant = await Mutant.deploy();

      // Renunciation IS correctly blocked on this mutant...
      await expect(mutant.connect(owner).renounceOwnership()).to.be.revertedWithCustomError(
        mutant,
        "OwnershipRenunciationDisabled",
      );

      // ...but a stranger can still seize ownership, which the production
      // "gains no ownership-changing path" assertion must reject.
      await mutant.connect(stranger).transferOwnership(stranger.address);
      expect(await mutant.owner()).to.equal(stranger.address);

      // The production contracts do not permit this.
      await expect(vault.connect(stranger).transferOwnership(stranger.address)).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );
      expect(await vault.owner()).to.equal(owner.address);
    });

    it("M2 — both production contracts block renunciation, so a one-sided fix is caught", async function () {
      // If a future edit fixed only one of the pair, exactly one of these two
      // assertions would fail. Stated explicitly because the sibling contracts
      // are near-identical implementations of the same semantics and have
      // diverged one-sidedly before.
      const blocked: boolean[] = [];
      for (const contract of [vault, sim]) {
        const reverted = await reverts(() => contract.connect(owner).renounceOwnership());
        blocked.push(reverted && (await contract.owner()) !== ZERO);
      }
      expect(blocked, "vault and simulator must both block renunciation").to.deep.equal([true, true]);
    });
  });

  // -------------------------------------------------------------------------
  // Structural assurance — catches a future refactor that silently drops the
  // override and lets the inherited transition become reachable again.
  //
  // EXACT PROOF BOUNDARY, stated rather than implied:
  //   - The ABI check proves the compiled `renounceOwnership` is NOT the
  //     inherited `nonpayable` implementation. If the override is deleted, the
  //     inherited one returns and its stateMutability reverts to `nonpayable`,
  //     failing this check. That is the whole of what it proves.
  //   - The AST check proves the override is declared in each contract's OWN
  //     source with an `override` specifier and a body whose only statement is a
  //     revert. It is source-level, so it also catches an override that compiles
  //     but no longer reverts.
  //   - NEITHER check proves that no OTHER function can zero the owner. That is
  //     a broader claim this suite does not make; the behavioural tests above
  //     cover the ownership surface that exists today, and nothing here would
  //     detect a newly added function that calls `_transferOwnership(address(0))`
  //     under a different name.
  // -------------------------------------------------------------------------

  describe("structural assurance", function () {
    const PRODUCTION = [
      { name: "WalletWallVault", path: "contracts/WalletWallVault.sol" },
      { name: "StablecoinVaultSimulator", path: "contracts/StablecoinVaultSimulator.sol" },
    ] as const;

    for (const { name, path } of PRODUCTION) {
      it(`${name}: the compiled renounceOwnership is the override, not the inherited one`, function () {
        const artifact = JSON.parse(readFileSync(resolve(`artifacts/${path}/${name}.json`), "utf8")) as {
          abi: { type: string; name?: string; stateMutability?: string }[];
        };

        const fn = artifact.abi.find((e) => e.type === "function" && e.name === "renounceOwnership");
        expect(fn, "renounceOwnership must remain present in the ABI").to.not.equal(undefined);
        expect(
          fn?.stateMutability,
          "stateMutability 'nonpayable' means the inherited Ownable implementation is back",
        ).to.equal("pure");
      });

      it(`${name}: declares an overriding renounceOwnership whose body only reverts`, function () {
        const contractAst = findContract(loadSourceAst(path), name);
        const fn = findFunctionDefinition(contractAst, "renounceOwnership");

        expect(fn.overrides, "must carry an `override` specifier").to.not.equal(undefined);
        expect(fn.stateMutability).to.equal("pure");

        // COVERAGE-AWARE, and this is not optional. `solidity-coverage` REWRITES the
        // source before compiling, injecting a `__NomicFoundationCoverage.sendHit(...)`
        // call ahead of each statement. A naive "the body has exactly one statement"
        // assertion therefore passes on a normal build and fails under coverage —
        // which is exactly what happened on the first CI run of this branch.
        //
        // The repository's convention for byte claims is to measure from a clean
        // non-instrumented build. The AST analogue is NOT to skip the check under
        // instrumentation — that would make it vacuously green in one of the two modes
        // — but to discount the injected statements and apply the SAME strict assertion
        // to what genuinely remains. The check stays discriminating in both modes.
        const statements = (fn.body?.statements ?? []) as AstStatement[];
        const authored = statements.filter((s) => !isCoverageHit(s));

        expect(authored, "the authored body must contain exactly one statement").to.have.length(1);
        expect(authored[0]?.nodeType, "that statement must be a revert").to.equal("RevertStatement");

        // And nothing in the body may return normally, instrumented or not.
        expect(
          statements.some((s) => s.nodeType === "Return"),
          "a return statement would give the function a non-reverting path",
        ).to.equal(false);
      });
    }
  });

  describe("pause semantics are unchanged", function () {
    it("owner can pause and unpause; a non-owner can do neither", async function () {
      await expect(vault.connect(stranger).pause()).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");

      await vault.connect(owner).pause();
      expect(await vault.paused()).to.equal(true);

      await expect(vault.connect(stranger).unpause()).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );

      await vault.connect(owner).unpause();
      expect(await vault.paused()).to.equal(false);
    });

    // EVIDENCE ONLY — deliberately NOT changed by this lane.
    //
    // While paused, WalletWallVault still accepts ETH: `deposit()`/`depositFor()`
    // carry no `whenNotPaused`, whereas every payout path does. So a frozen vault
    // keeps taking in funds it cannot pay out. The sibling simulator does NOT
    // share this shape — its `deposit`/`depositFor` ARE `whenNotPaused` — which
    // makes this a genuine one-sided divergence between two contracts that
    // otherwise implement the same semantics.
    //
    // It compounds the T0 hazard (a permanently frozen vault would go on
    // accepting deposits) but it is a SEPARATE defect: closing it is not required
    // to make renunciation unreachable, and widening this PR to change an inflow
    // path would put a behavioural change in a remediation that otherwise has
    // none. Pinned here so the asymmetry is recorded rather than rediscovered.
    it("EVIDENCE: the vault still accepts deposits while paused; the simulator does not", async function () {
      await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
      await vault.connect(owner).pause();

      // Vault: inflow succeeds while every payout path is frozen.
      await vault.connect(owner).deposit({ value: 1n });
      expect((await vault.getVault(owner.address)).balance).to.equal(1n);

      // Simulator: inflow is refused while paused.
      await sim.connect(owner).pause();
      await expect(sim.connect(owner).deposit(1n)).to.be.revertedWithCustomError(sim, "EnforcedPause");
    });

    it("pause still gates recovery execution on both contracts", async function () {
      await vault.connect(owner).pause();
      await expect(vault.executeRecovery(owner.address)).to.be.revertedWithCustomError(vault, "EnforcedPause");

      await sim.connect(owner).pause();
      await expect(sim.executeRecovery(owner.address)).to.be.revertedWithCustomError(sim, "EnforcedPause");
    });
  });
});
