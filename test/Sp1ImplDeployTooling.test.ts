/**
 * SP1 implementation lane: scripts/deploy-zk-verifier.ts takes its inputs only from a designation
 * (scripts/lib/zk-verifier-deployment.ts; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * Off a local chain the SP1 verifier, its expected runtime code hash and PROGRAM_VKEY come only from an accepted
 * designation, and the wrapper only from the latest recorded build; no environment variable or flag can replace them,
 * and asking is refused before any transaction. Before the wrapper is deployed the tooling measures, on the target
 * chain: the designated verifier's runtime code hash, the per-chain execution verdicts (with the canary's positive
 * control on the in-process EVM), the halt principal's separation from the deployer, and the registry (no halted
 * identity, on any chain). After deploying it reads the wrapper back. Every RPC failure stops it.
 *
 * The local, test-only path (chains 31337/1337 with ALLOW_MOCK_SP1=true) is segregated: it is the only path that
 * accepts a mock, its wrapper's SP1 verifier runs mock code the binding gate refuses off a local chain, and nothing it
 * deploys satisfies a production check.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import assert from "node:assert/strict";

import { ethers, networkHelpers } from "./helpers/connection";
import { deployPinnedSp1Verifier, v610Runtime } from "./helpers/sp1PinnedVerifier";
import { registryFromProfiles } from "./helpers/registryHelpers";
import { readDesignations, type ProgramDesignation } from "../scripts/lib/sp1-designation";
import { readWrapperBuilds, type WrapperBuild } from "../scripts/lib/sp1-wrapper-build";
import { patchPairingToEmptyAccount } from "../scripts/lib/sp1-chain-execution";
import { readRegistry } from "../scripts/lib/sp1-registry";
import { bindingRefusals, profileVerifier, readHaltScope } from "../scripts/lib/verifier-binding";
import {
  TEST_ONLY_MOCK_VKEY,
  deployPlannedWrapper,
  planWrapperDeployment,
  preDeploymentChecks,
  readBackErrors,
  type PlanInput,
} from "../scripts/lib/zk-verifier-deployment";

const SEPOLIA = 11155111n;
const LOCAL = 31337n;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

describe("SP1 implementation lane — deploy-zk-verifier takes its inputs only from a designation", function () {
  let deployer: any, haltPrincipal: any, stranger: any;
  let designations: ProgramDesignation[];
  let builds: WrapperBuild[];
  let d1: ProgramDesignation;

  before(async function () {
    [deployer, haltPrincipal, stranger] = await ethers.getSigners();
    designations = readDesignations(".");
    builds = readWrapperBuilds(".");
    d1 = designations[0];
  });

  const input = (overrides: Partial<PlanInput> = {}): PlanInput => ({
    chainId: SEPOLIA,
    env: { HALT_PRINCIPAL_ADDRESS: haltPrincipal.address },
    deployer: deployer.address,
    localHaltPrincipal: haltPrincipal.address,
    designations,
    builds,
    currentBuildErrors: [],
    registry: readRegistry("."),
    ...overrides,
  });

  describe("planning, before any transaction", function () {
    it("off a local chain the plan is the designation's: its verifier, its vkey, the latest recorded build", function () {
      const plan = planWrapperDeployment(input());
      expect(plan.mode).to.equal("DESIGNATED");
      expect(plan.designation?.id).to.equal(d1.id);
      expect(plan.sp1Verifier).to.equal(d1.verifier.address);
      expect(plan.expectedSp1CodeKeccak).to.equal(d1.verifier.runtimeCodeKeccak);
      expect(plan.programVKey).to.equal(d1.programVKey);
      expect(plan.build.id).to.equal(builds[builds.length - 1].id);
      expect(plan.haltPrincipal).to.equal(haltPrincipal.address);
    });

    const refused: [string, () => PlanInput, RegExp][] = [
      [
        "an SP1_VERIFIER_ADDRESS override",
        () => input({ env: { HALT_PRINCIPAL_ADDRESS: haltPrincipal.address, SP1_VERIFIER_ADDRESS: stranger.address } }),
        /no override exists on chain 11155111/,
      ],
      [
        "a PROGRAM_VKEY override, even the designated one",
        () => input({ env: { HALT_PRINCIPAL_ADDRESS: haltPrincipal.address, PROGRAM_VKEY: d1.programVKey } }),
        /no override exists on chain 11155111/,
      ],
      [
        "the mock flag",
        () => input({ env: { HALT_PRINCIPAL_ADDRESS: haltPrincipal.address, ALLOW_MOCK_SP1: "true" } }),
        /no override exists on chain 11155111/,
      ],
      ["no halt principal", () => input({ env: {} }), /HALT_PRINCIPAL_ADDRESS is required/],
      [
        "the deployer as halt principal",
        () => input({ env: { HALT_PRINCIPAL_ADDRESS: deployer.address } }),
        /the halt principal must not be the deployer/,
      ],
      [
        "an unknown designation",
        () =>
          input({
            env: { HALT_PRINCIPAL_ADDRESS: haltPrincipal.address, SP1_DESIGNATION_ID: "mldsa65-withdrawal-d9" },
          }),
        /no designation mldsa65-withdrawal-d9/,
      ],
      [
        "a compiled wrapper that is not a recorded build",
        () => input({ currentBuildErrors: ["the compiled wrapper differs"] }),
        /not the latest recorded build/,
      ],
      [
        "a build that pins another verifier",
        () => {
          const other = clone(builds);
          other[other.length - 1].pins.sp1VerifierCodehash = ethers.id("another verifier");
          return input({ builds: other });
        },
        /pins another SP1 verifier/,
      ],
      [
        "a designation whose identity the registry records halted on any chain",
        () =>
          input({
            registry: registryFromProfiles(84532n, [
              {
                address: stranger.address,
                hasCode: true,
                genuineWrapper: true,
                wrapperBuild: builds[0].id,
                pinnedSp1VerifierCodehash: builds[0].pins.sp1VerifierCodehash,
                algorithmId: null,
                sp1Verifier: d1.verifier.address,
                sp1VerifierCodeKeccak: d1.verifier.runtimeCodeKeccak,
                programVKey: d1.programVKey,
                haltPrincipal: haltPrincipal.address,
                halted: true,
                identity: d1.identity,
              },
            ]),
          }),
        /recorded HALTED/,
      ],
      ["Ethereum mainnet", () => input({ chainId: 1n }), /MAINNET/],
    ];
    for (const [label, make, rule] of refused) {
      it(`refuses ${label}`, function () {
        assert.throws(() => planWrapperDeployment(make()), rule);
      });
    }

    it("chooses the designation only from accepted ones: two compatible designations need an explicit choice", function () {
      const d2 = { ...clone(d1), id: "mldsa65-withdrawal-d2", sequence: 2, programVKey: ethers.id("d2 vkey") };
      assert.throws(
        () => planWrapperDeployment(input({ designations: [d1, d2] })),
        /choose one with SP1_DESIGNATION_ID/,
      );
      const chosen = planWrapperDeployment(
        input({
          designations: [d1, d2],
          env: { HALT_PRINCIPAL_ADDRESS: haltPrincipal.address, SP1_DESIGNATION_ID: "mldsa65-withdrawal-d2" },
        }),
      );
      expect(chosen.programVKey).to.equal(ethers.id("d2 vkey"));
    });

    it("the local test path is the only one that takes a mock, and only with the flag on a local chain", function () {
      const mock = planWrapperDeployment(input({ chainId: LOCAL, env: { ALLOW_MOCK_SP1: "true" } }));
      expect([mock.mode, mock.designation, mock.programVKey]).to.deep.equal([
        "LOCAL_TEST_MOCK",
        null,
        TEST_ONLY_MOCK_VKEY,
      ]);
      const designated = planWrapperDeployment(input({ chainId: LOCAL, env: {} }));
      expect([designated.mode, designated.programVKey]).to.deep.equal(["LOCAL_DESIGNATED", d1.programVKey]);
      expect(designated.haltPrincipal).to.equal(haltPrincipal.address);
    });
  });

  describe("on the target chain, before deploying", function () {
    let v610: string;

    before(async function () {
      v610 = await deployPinnedSp1Verifier();
    });

    const localPlan = (sp1: string) => ({
      ...planWrapperDeployment(input({ chainId: LOCAL, env: {} })),
      sp1Verifier: sp1,
    });

    it("passes for the designated code that gives the required verdicts, with the canary's positive control", async function () {
      const report = await preDeploymentChecks(ethers.provider, localPlan(v610), ethers.provider as any);
      expect(report).to.deep.include({
        codeKeccak: d1.verifier.runtimeCodeKeccak,
        executionPass: true,
        canaryDetects: true,
      });
    });

    it("refuses other code at the verifier address, and an address without code", async function () {
      const mock = await (await ethers.getContractFactory("MockSP1Verifier")).deploy();
      await assert.rejects(
        preDeploymentChecks(ethers.provider, localPlan(await mock.getAddress()), ethers.provider as any),
        /not the designated code/,
      );
      await assert.rejects(
        preDeploymentChecks(ethers.provider, localPlan(stranger.address), ethers.provider as any),
        /not the designated code/,
      );
    });

    it("refuses a chain where the same code gives other verdicts (its pairing precompile broken), by execution", async function () {
      const broken = ethers.getAddress(ethers.dataSlice(ethers.id("sp1-impl deploy: broken chain"), 12));
      await networkHelpers.setCode(broken, patchPairingToEmptyAccount(await v610Runtime()));
      // The chain reports the designated code for the verifier (getCode) while its calls run without the precompile.
      const chain = new Proxy(ethers.provider, {
        get(t, prop) {
          if (prop === "call")
            return (tx: any) => t.call({ ...tx, to: tx.to?.toLowerCase() === v610.toLowerCase() ? broken : tx.to });
          const value = Reflect.get(t, prop, t);
          return typeof value === "function" ? value.bind(t) : value;
        },
      });
      await assert.rejects(
        preDeploymentChecks(chain, localPlan(v610), ethers.provider as any),
        /per-chain execution check failed: .*canary: success/,
      );
    });

    it("an RPC that does not answer stops it: no code read, no verdict, no deployment", async function () {
      for (const method of ["getCode", "call"]) {
        const flaky = new Proxy(ethers.provider, {
          get(t, prop) {
            if (prop === method)
              return async () => Promise.reject(Object.assign(new Error("Too Many Requests"), { code: -32005 }));
            const value = Reflect.get(t, prop, t);
            return typeof value === "function" ? value.bind(t) : value;
          },
        });
        await assert.rejects(
          preDeploymentChecks(flaky, localPlan(v610), ethers.provider as any),
          /Too Many Requests|no answer/,
          method,
        );
      }
    });
  });

  describe("deploying, and reading back", function () {
    it("the designated path deploys a wrapper the read-back and the binding gate accept as designated", async function () {
      const planned = {
        ...planWrapperDeployment(input({ chainId: LOCAL, env: {} })),
        sp1Verifier: await deployPinnedSp1Verifier(),
      };
      const { wrapper, plan } = await deployPlannedWrapper(ethers as any, deployer, planned);
      expect(await readBackErrors(ethers.provider, wrapper, plan, builds)).to.deep.equal([]);
      const p = await profileVerifier(ethers.provider, wrapper, builds);
      expect([p.identity, p.wrapperBuild, p.halted]).to.deep.equal([d1.identity, builds[builds.length - 1].id, false]);
    });

    it("the read-back refuses a wrapper that is not what the plan names", async function () {
      const planned = {
        ...planWrapperDeployment(input({ chainId: LOCAL, env: {} })),
        sp1Verifier: await deployPinnedSp1Verifier(),
      };
      const { wrapper, plan } = await deployPlannedWrapper(ethers as any, deployer, planned);
      const cases: [string, any, RegExp][] = [
        ["another vkey", { ...plan, programVKey: ethers.id("x") }, /PROGRAM_VKEY/],
        ["another halt principal", { ...plan, haltPrincipal: stranger.address }, /halt principal/],
        ["another verifier", { ...plan, sp1Verifier: stranger.address }, /SP1 verifier/],
      ];
      for (const [label, other, rule] of cases) {
        expect((await readBackErrors(ethers.provider, wrapper, other, builds)).join("\n"), label).to.match(rule);
      }
      expect((await readBackErrors(ethers.provider, stranger.address, plan, builds)).join("\n")).to.match(
        /recorded build/,
      );
    });

    it("the local test path puts a mock behind a genuine wrapper, labelled, and the gate refuses it off a local chain", async function () {
      const planned = planWrapperDeployment(input({ chainId: LOCAL, env: { ALLOW_MOCK_SP1: "true" } }));
      const { wrapper, plan } = await deployPlannedWrapper(ethers as any, deployer, planned);
      expect(await readBackErrors(ethers.provider, wrapper, plan, builds)).to.deep.equal([]);
      const p = await profileVerifier(ethers.provider, wrapper, builds);
      expect(p.genuineWrapper).to.equal(true);
      expect(p.sp1VerifierCodeKeccak).to.not.equal(d1.verifier.runtimeCodeKeccak);
      const refusals = bindingRefusals({
        consumer: "WalletWallVault",
        target: p,
        chainId: SEPOLIA,
        signer: deployer.address,
        allowMockSp1: false,
        current: null,
        currentIdentity: null,
        targetIdentityRecordedHalted: false,
        scope: readHaltScope(),
        designations: [],
        registered: [p],
        registry: registryFromProfiles(SEPOLIA, [p]),
      }).join("\n");
      expect(refusals).to.match(/not the code its build pins/);
      expect(refusals).to.match(/matches no designation/);
    });

    it("the script itself reads the SP1 verifier and PROGRAM_VKEY only through the plan", function () {
      const script = readFileSync(resolve("scripts/deploy-zk-verifier.ts"), "utf8");
      expect(script).to.match(/planWrapperDeployment\(/);
      expect(script).to.match(/assertDeployableChain\(/);
      expect(script.indexOf("assertDeployableChain(")).to.be.lessThan(script.indexOf("planWrapperDeployment("));
      expect(script.indexOf("preDeploymentChecks(")).to.be.lessThan(script.indexOf("deployPlannedWrapper("));
      expect(script.indexOf("deployPlannedWrapper(")).to.be.lessThan(script.indexOf("readBackErrors("));
      expect(script).to.not.match(/process\.env\.(SP1_VERIFIER_ADDRESS|PROGRAM_VKEY)/);
      expect(script).to.not.match(/getContractFactory\("ZKMLDSAVerifier"\)/);
    });
  });
});
