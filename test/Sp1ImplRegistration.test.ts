/**
 * SP1 implementation lane: registry facts are measured, never typed (scripts/lib/sp1-registration.ts,
 * scripts/register-sp1-wrapper.ts). A WRAPPER_REGISTERED fact comes from the deployment transaction's receipt and the
 * wrapper's measured profile (its recorded build, SP1 verifier code, PROGRAM_VKEY, identity, halt principal), joined to
 * the designation of that identity; a WRAPPER_HALTED fact from the halt transaction's receipt (its VerifierHalted
 * event) and the wrapper's measured state. Each is validated against the extended registry before it is written, and
 * neither tool sends a transaction.
 */
import { expect } from "chai";
import assert from "node:assert/strict";

import { ethers } from "./helpers/connection";
import { deployPinnedSp1Verifier } from "./helpers/sp1PinnedVerifier";
import { readDesignations } from "../scripts/lib/sp1-designation";
import { readWrapperBuilds } from "../scripts/lib/sp1-wrapper-build";
import { readRegistry, registryErrors, type RegistryDoc } from "../scripts/lib/sp1-registry";
import { haltFact, registrationFact } from "../scripts/lib/sp1-registration";
import { deployPlannedWrapper, planWrapperDeployment } from "../scripts/lib/zk-verifier-deployment";

describe("SP1 implementation lane — registry facts from chain reads", function () {
  let deployer: any, haltPrincipal: any, stranger: any;
  const designations = () => readDesignations(".");
  const builds = () => readWrapperBuilds(".");

  /** The transaction that created `address`, found by its receipt among the latest blocks. */
  async function deploymentTxOf(address: string): Promise<string> {
    const latest = await ethers.provider.getBlockNumber();
    for (let n = latest; n > latest - 8 && n >= 0; n--) {
      for (const hash of (await ethers.provider.getBlock(n))!.transactions) {
        const r = await ethers.provider.getTransactionReceipt(hash);
        if (r?.contractAddress && ethers.getAddress(r.contractAddress) === ethers.getAddress(address)) return hash;
      }
    }
    throw new Error(`no deployment of ${address} in the latest blocks`);
  }

  async function deployDesignated() {
    const planned = {
      ...planWrapperDeployment({
        chainId: 31337n,
        env: {},
        deployer: deployer.address,
        localHaltPrincipal: haltPrincipal.address,
        designations: designations(),
        builds: builds(),
        currentBuildErrors: [],
        registry: readRegistry("."),
      }),
      sp1Verifier: await deployPinnedSp1Verifier(),
    };
    const { wrapper } = await deployPlannedWrapper(ethers as any, deployer, planned);
    return { wrapper, deployment: await deploymentTxOf(wrapper) };
  }

  before(async function () {
    [deployer, haltPrincipal, stranger] = await ethers.getSigners();
  });

  it("a registration measured from the chain is the designated wrapper's, and passes the registry's rules", async function () {
    const { wrapper, deployment } = await deployDesignated();
    const registry = readRegistry(".");
    const fact = await registrationFact(ethers.provider, {
      wrapper,
      deploymentTx: deployment,
      designations: designations(),
      builds: builds(),
      registry,
    });
    const d1 = designations()[0];
    expect(fact).to.deep.include({
      seq: 1,
      kind: "WRAPPER_REGISTERED",
      chainId: "31337",
      address: wrapper,
      identity: d1.identity,
      wrapperBuild: builds()[builds().length - 1].id,
      designation: d1.id,
      programVKey: d1.programVKey,
      haltPrincipal: haltPrincipal.address,
      replaces: null,
    });
    expect(fact.sp1Verifier!.runtimeCodeKeccak).to.equal(d1.verifier.runtimeCodeKeccak);
    expect(fact.deployment).to.deep.include({ txHash: deployment, deployer: deployer.address });
    expect(registryErrors({ ...registry, facts: [fact] }, builds(), designations())).to.deep.equal([]);
  });

  it("refuses a transaction that did not deploy the wrapper, and a wrapper no designation names", async function () {
    const { wrapper } = await deployDesignated();
    const other = await (await deployer.sendTransaction({ to: stranger.address, value: 1n })).wait();
    await assert.rejects(
      registrationFact(ethers.provider, {
        wrapper,
        deploymentTx: other!.hash,
        designations: designations(),
        builds: builds(),
        registry: readRegistry("."),
      }),
      /did not deploy/,
    );
    const mockPlan = planWrapperDeployment({
      chainId: 31337n,
      env: { ALLOW_MOCK_SP1: "true" },
      deployer: deployer.address,
      localHaltPrincipal: haltPrincipal.address,
      designations: designations(),
      builds: builds(),
      currentBuildErrors: [],
      registry: readRegistry("."),
    });
    const { wrapper: mock } = await deployPlannedWrapper(ethers as any, deployer, mockPlan);
    await assert.rejects(
      registrationFact(ethers.provider, {
        wrapper: mock,
        deploymentTx: await deploymentTxOf(mock),
        designations: designations(),
        builds: builds(),
        registry: readRegistry("."),
      }),
      /no designation/,
    );
  });

  it("a halt measured from its transaction appends the halt fact; a wrapper still ACTIVE is refused one", async function () {
    const { wrapper, deployment } = await deployDesignated();
    const base = readRegistry(".");
    const registration = await registrationFact(ethers.provider, {
      wrapper,
      deploymentTx: deployment,
      designations: designations(),
      builds: builds(),
      registry: base,
    });
    const registry: RegistryDoc = { ...base, facts: [registration] };
    await assert.rejects(
      haltFact(ethers.provider, {
        wrapper,
        haltTx: deployment,
        reason: "VERIFIER_SOUNDNESS",
        registry,
        builds: builds(),
      }),
      /no VerifierHalted|not HALTED/,
    );
    const zk = await ethers.getContractAt("ZKMLDSAVerifier", wrapper);
    const halt = await (await zk.connect(haltPrincipal).halt()).wait();
    const fact = await haltFact(ethers.provider, {
      wrapper,
      haltTx: halt!.hash,
      reason: "VERIFIER_SOUNDNESS",
      registry,
      builds: builds(),
    });
    expect(fact).to.deep.include({ seq: 2, kind: "WRAPPER_HALTED", address: wrapper, identity: registration.identity });
    expect(registryErrors({ ...registry, facts: [registration, fact] }, builds(), designations())).to.deep.equal([]);
    await assert.rejects(
      haltFact(ethers.provider, { wrapper, haltTx: halt!.hash, reason: "BECAUSE", registry, builds: builds() }),
      /reason/,
    );
  });

  it("an RPC that does not answer writes nothing", async function () {
    const { wrapper, deployment } = await deployDesignated();
    const flaky = new Proxy(ethers.provider, {
      get(t, prop) {
        if (prop === "getTransactionReceipt")
          return async () => Promise.reject(Object.assign(new Error("Too Many Requests"), { code: -32005 }));
        const value = Reflect.get(t, prop, t);
        return typeof value === "function" ? value.bind(t) : value;
      },
    });
    await assert.rejects(
      registrationFact(flaky, {
        wrapper,
        deploymentTx: deployment,
        designations: designations(),
        builds: builds(),
        registry: readRegistry("."),
      }),
      /Too Many Requests/,
    );
  });
});
