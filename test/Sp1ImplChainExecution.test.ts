/**
 * SP1 implementation lane: CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK (SP1-TD1 finding TD1-N8;
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * A code hash pins bytes, not behaviour: the Groth16 verifier ANDs the pairing call's success with its first output
 * word, so on a chain without the 0x08 precompile an odd first word passes. Before a wrapper is deployed on a chain,
 * and whenever that chain's precompiles may have changed, the designated verifier is executed there by eth_call:
 *   - a real v6.1.0 proof (a third party's, from a successful mainnet call; it authenticates itself) is accepted;
 *   - the same proof with one public-value bit flipped is refused with ProofInvalid;
 *   - the odd-word canary (v6.1.0's selector, exit code 0, the vk root, nonce 0, eight proof words of 1) is refused
 *     with ProofInvalid — and its positive control shows it is accepted by the same code whose pairing calls reach an
 *     empty account, so the canary does detect the broken environment.
 * The calldata is rebuilt from committed evidence and must equal what SP1-TD1 sent, byte for byte; the required
 * verdicts live in code, never in an observation; an RPC that does not answer produces no verdict at all.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import assert from "node:assert/strict";

import { ethers, networkHelpers } from "./helpers/connection";
import { deployPinnedSp1Verifier, v610Runtime } from "./helpers/sp1PinnedVerifier";
import { readDesignations } from "../scripts/lib/sp1-designation";
import {
  CHAIN_EXECUTION_OBSERVATION_REL,
  PROOF_INVALID,
  REQUIRED_VERDICTS,
  SUPPORTED_DEPLOYMENT_CHAINS,
  canaryPositiveControl,
  chainExecutionCalls,
  chainExecutionObservationErrors,
  patchPairingToEmptyAccount,
  runChainExecutionCheck,
  type ChainExecutionObservation,
} from "../scripts/lib/sp1-chain-execution";

const TD1_EXEC = JSON.parse(readFileSync(resolve("evidence/zk/sp1-td1/observations/chain-execution.raw.json"), "utf8"));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

describe("SP1 implementation lane — the per-chain execution check", function () {
  const d1 = () => readDesignations(".")[0];

  it("rebuilds the exact calldata SP1-TD1 sent on every chain from committed evidence", function () {
    const calls = chainExecutionCalls(d1(), ".");
    expect(calls.real).to.deep.equal({ to: TD1_EXEC.calls.v610RealProof.to, data: TD1_EXEC.calls.v610RealProof.data });
    expect(calls.tampered).to.deep.equal({
      to: TD1_EXEC.calls.v610TamperedPublicValues.to,
      data: TD1_EXEC.calls.v610TamperedPublicValues.data,
    });
    expect(calls.canary).to.deep.equal({
      to: TD1_EXEC.calls.v610OddWordCanary.to,
      data: TD1_EXEC.calls.v610OddWordCanary.data,
    });
    expect(REQUIRED_VERDICTS).to.deep.equal({
      real: "success",
      tampered: `revert ${PROOF_INVALID}`,
      canary: `revert ${PROOF_INVALID}`,
    });
    expect(PROOF_INVALID).to.equal(ethers.id("ProofInvalid()").slice(0, 10));
  });

  describe("on a chain (here, the local EVM) the designated code passes and a broken environment does not", function () {
    let verifier: string;
    const at = (address: string) => {
      const calls = chainExecutionCalls(d1(), ".");
      return {
        real: { ...calls.real, to: address },
        tampered: { ...calls.tampered, to: address },
        canary: { ...calls.canary, to: address },
      };
    };

    before(async function () {
      verifier = await deployPinnedSp1Verifier();
    });

    it("the real v6.1.0 bytes give the required verdicts", async function () {
      const result = await runChainExecutionCheck(ethers.provider, at(verifier));
      expect(result.verdicts).to.deep.equal(REQUIRED_VERDICTS);
      expect([result.pass, result.failures]).to.deep.equal([true, []]);
    });

    it("the same code whose pairing calls reach an empty account accepts the canary, and fails the check", async function () {
      const patched = ethers.getAddress(ethers.dataSlice(ethers.id("sp1-impl: no pairing precompile"), 12));
      await networkHelpers.setCode(patched, patchPairingToEmptyAccount(await v610Runtime()));
      const result = await runChainExecutionCheck(ethers.provider, at(patched));
      expect(result.verdicts.canary).to.equal("success");
      expect(result.pass).to.equal(false);
      expect(result.failures.join("\n")).to.match(/canary: success, required revert 0x7fcdd1f4/);
    });

    it("the canary's positive control fires (and would fail if the canary could not see a missing precompile)", async function () {
      const codehash = d1().verifier.runtimeCodeKeccak;
      const control = await canaryPositiveControl(ethers.provider, at(verifier).canary.data, codehash);
      expect(control).to.deep.equal({
        pinnedCode: `revert ${PROOF_INVALID}`,
        withoutPairingPrecompile: "success",
        detects: true,
      });
      // A "canary" that is a valid proof would be accepted by both: no detector at all.
      const notACanary = await canaryPositiveControl(ethers.provider, at(verifier).real.data, codehash);
      expect(notACanary.detects).to.equal(false);
      // The code it installs is the designation's, checked by hash: there is no default to fall back on.
      await assert.rejects(
        canaryPositiveControl(ethers.provider, at(verifier).canary.data, ethers.ZeroHash),
        /is not the designated verifier's/,
      );
    });

    it("an accept-all verifier fails: tampering must be refused, and with ProofInvalid exactly", async function () {
      const acceptAll = await (await ethers.getContractFactory("AcceptAllRouteVerifierProbe")).deploy(ethers.ZeroHash);
      const result = await runChainExecutionCheck(ethers.provider, at(await acceptAll.getAddress()));
      expect(result.pass).to.equal(false);
      expect(result.failures.join("\n")).to.match(/tampered: success, required revert/);
    });

    it("a refusal with other revert data is not the required verdict", async function () {
      const calls = at(verifier);
      // Another selector in the proof bytes: refused, but with WrongVerifierSelector, not ProofInvalid.
      const otherSelector = {
        ...calls,
        tampered: { ...calls.canary, data: calls.canary.data.replace("4388a21c", "deadbeef") },
      };
      const result = await runChainExecutionCheck(ethers.provider, otherSelector);
      expect(result.verdicts.tampered).to.match(/^revert 0x988066a1/);
      expect(result.pass).to.equal(false);
    });

    it("an RPC that does not answer gives no verdict: the check throws, it never reads a failure as a refusal", async function () {
      const calls = at(verifier);
      for (const [label, error] of [
        ["rate limit", Object.assign(new Error("Too Many Requests"), { code: -32005 })],
        ["timeout", Object.assign(new Error("request timeout"), { code: "TIMEOUT" })],
        ["refused connection", new Error("connect ECONNREFUSED 127.0.0.1:8545")],
        [
          "ethers: a rate limit",
          { code: "CALL_EXCEPTION", data: null, info: { error: { code: -32005, message: "limit" } } },
        ],
      ] as [string, unknown][]) {
        const flaky = new Proxy(ethers.provider, {
          get(t, prop) {
            if (prop === "call") {
              return async (tx: { data: string }) => {
                if (tx.data === calls.tampered.data) throw error;
                return t.call(tx as any);
              };
            }
            const value = Reflect.get(t, prop, t);
            return typeof value === "function" ? value.bind(t) : value;
          },
        });
        await assert.rejects(runChainExecutionCheck(flaky, calls), /got no answer from the chain/, label);
      }
    });
  });

  describe("the committed read-only measurement", function () {
    let observation: ChainExecutionObservation;

    before(function () {
      observation = JSON.parse(readFileSync(resolve(CHAIN_EXECUTION_OBSERVATION_REL), "utf8"));
    });

    it("covers every supported deployment chain (and the trust target's mainnets), each through two agreeing providers", function () {
      expect(SUPPORTED_DEPLOYMENT_CHAINS).to.deep.equal(["11155111", "84532"]);
      expect(chainExecutionObservationErrors(observation, d1(), ".")).to.deep.equal([]);
      for (const chainId of ["1", "8453", "11155111", "84532"]) {
        const c = observation.chains[chainId];
        expect(c, chainId).to.not.equal(undefined);
        expect(Object.keys(c.providers).length, chainId).to.be.greaterThanOrEqual(2);
        expect(c.verdicts, chainId).to.deep.equal(REQUIRED_VERDICTS);
        expect(c.codeKeccak, chainId).to.equal(d1().verifier.runtimeCodeKeccak);
      }
    });

    const refused: [string, (o: ChainExecutionObservation) => void, RegExp][] = [
      ["calldata that is not the rebuilt call", (o) => (o.calls.canary.data = o.calls.real.data), /calldata/],
      ["a verdict relaxed in the observation", (o) => (o.chains["84532"].verdicts.canary = "success"), /84532.*canary/],
      [
        "a provider that disagrees",
        (o) => (Object.values(o.chains["11155111"].providers)[1].verdicts.real = "revert 0x"),
        /11155111.*providers/,
      ],
      [
        "another block at one provider",
        (o) => (Object.values(o.chains["1"].providers)[0].blockHash = ethers.ZeroHash),
        /\b1\b.*block/,
      ],
      ["other verifier code", (o) => (o.chains["8453"].codeKeccak = ethers.ZeroHash), /8453.*code/],
      ["a supported chain missing", (o) => delete o.chains["84532"], /84532.*not measured/],
      [
        "one provider only",
        (o) => delete o.chains["11155111"].providers[Object.keys(o.chains["11155111"].providers)[1]],
        /11155111.*two providers/,
      ],
      ["another proof source", (o) => (o.proofSource.sha256 = "00".repeat(32)), /proof source/],
      ["another verifier", (o) => (o.verifier.address = ethers.ZeroAddress), /verifier/],
      // Review finding F7: the control is judged from its recorded verdicts, never from its flag (P5).
      [
        "a positive control whose verdicts show it did not fire, flagged as firing",
        (o) =>
          (o.canaryPositiveControl = { pinnedCode: "success", withoutPairingPrecompile: "revert 0x", detects: true }),
        /positive control did not fire/,
      ],
      [
        "a positive control that fired, flagged as not firing",
        (o) => (o.canaryPositiveControl.detects = false),
        /positive control/,
      ],
      [
        "a measurement by a script that is not this tree's",
        (o) => (o.tool.scriptSha256 = "00".repeat(32)),
        /not made by scripts\/check-sp1-chain-execution\.ts as committed/,
      ],
      [
        "a measurement by another script",
        (o) => (o.tool.script = "scripts/no-such-script.ts"),
        /not made by scripts\/check-sp1-chain-execution\.ts as committed/,
      ],
    ];
    for (const [label, change, rule] of refused) {
      it(`refuses ${label}`, function () {
        const o = clone(observation);
        change(o);
        expect(chainExecutionObservationErrors(o, d1(), ".").join("\n")).to.match(rule);
      });
    }
  });
});
