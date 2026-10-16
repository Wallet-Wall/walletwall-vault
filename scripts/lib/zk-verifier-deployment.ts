/**
 * ZKMLDSAVerifier deployment with designation-only inputs (the SP1 implementation lane;
 * docs/SP1_Implementation_Pin_Designation_Registry.md). Used by scripts/deploy-zk-verifier.ts and its tests.
 *
 *   plan     (pure, before any transaction) — off a local chain the SP1 verifier, its runtime code hash and PROGRAM_VKEY
 *            come only from an accepted designation (compatible with the latest recorded wrapper build, its identity
 *            halted nowhere the registry records), the wrapper only from that build, and the halt principal from
 *            HALT_PRINCIPAL_ADDRESS, never the deployer. SP1_VERIFIER_ADDRESS, PROGRAM_VKEY and ALLOW_MOCK_SP1 are
 *            refused there; mainnets are refused outright.
 *   check    (on the target chain, read-only) — the designated verifier's runtime code hash and the per-chain execution
 *            verdicts, with the canary's positive control on the in-process EVM. Every RPC failure stops it.
 *   deploy   — the wrapper, from the compiled (recorded) build.
 *   read back — the deployed wrapper's build, verifier, code, vkey, halt principal and state, measured.
 *
 * The local, test-only path (chain 31337/1337 with ALLOW_MOCK_SP1=true) is the only one that takes a mock: it builds
 * the genuine wrapper over the designated verifier's real bytes, then replaces that code with an always-accepting mock
 * (hardhat_setCode, which only a development chain has). The binding gate refuses such a wrapper off a local chain (its
 * SP1 verifier is not the code its build pins), so nothing it deploys satisfies a production check.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getAddress, isHexString, keccak256, toUtf8Bytes, ZeroHash, type Provider, type Signer } from "ethers";

import { FORBIDDEN_MAINNET_CHAIN_IDS, resolveHaltPrincipal } from "./deployment-guards";
import {
  VERIFIER_BYTECODE_REL,
  canaryPositiveControl,
  chainExecutionCalls,
  runChainExecutionCheck,
  type DevProvider,
  type Verdicts,
} from "./sp1-chain-execution";
import { compatibleDesignations, type ProgramDesignation } from "./sp1-designation";
import { finalizedBlock } from "./sp1-registration";
import { registryState, type RegistryDoc } from "./sp1-registry";
import type { WrapperBuild } from "./sp1-wrapper-build";
import { LOCAL_CHAIN_IDS, profileVerifier } from "./verifier-binding";

/** The vkey of the local test path: a label, never a program. */
export const TEST_ONLY_MOCK_VKEY = keccak256(toUtf8Bytes("TEST_ONLY_MOCK_VKEY"));

export type DeploymentMode = "DESIGNATED" | "LOCAL_DESIGNATED" | "LOCAL_TEST_MOCK";

export interface PlanInput {
  chainId: bigint;
  /** The operator's environment (read for the keys below only). */
  env: Record<string, string | undefined>;
  deployer: string;
  /** The second local account, the halt principal's default on a local chain only. */
  localHaltPrincipal?: string;
  designations: readonly ProgramDesignation[];
  builds: readonly WrapperBuild[];
  /** How the compiled wrapper departs from the latest recorded build (scripts/lib/sp1-wrapper-build.ts). */
  currentBuildErrors: readonly string[];
  registry: RegistryDoc;
}

export interface WrapperDeploymentPlan {
  chainId: bigint;
  mode: DeploymentMode;
  designation: ProgramDesignation | null;
  build: WrapperBuild;
  /** Where the SP1 verifier is; null on a local chain until its designated bytes are deployed there. */
  sp1Verifier: string | null;
  expectedSp1CodeKeccak: string;
  programVKey: string;
  haltPrincipal: string;
}

const isLocal = (chainId: bigint) => (LOCAL_CHAIN_IDS as readonly bigint[]).includes(chainId);

/** The designation to deploy: the one named, or the only accepted one (compatible with the build, halted nowhere). */
function chooseDesignation(
  input: PlanInput,
  build: WrapperBuild | undefined,
  errors: string[],
): ProgramDesignation | null {
  const halts = registryState(input.registry);
  const wanted = input.env.SP1_DESIGNATION_ID;
  if (wanted !== undefined && wanted !== "") {
    const named = input.designations.find((d) => d.id === wanted);
    if (!named) errors.push(`no designation ${wanted}`);
    return named ?? null;
  }
  const compatible = build ? compatibleDesignations(build, input.designations) : [];
  if (build && compatible.length === 0) {
    errors.push(
      `wrapper build ${build.id} pins another SP1 verifier than every designation (${input.designations.map((d) => d.id).join(", ")})`,
    );
    return null;
  }
  const accepted = compatible.filter((d) => halts.haltsOfIdentity(d.identity).length === 0);
  if (accepted.length === 1) return accepted[0];
  if (accepted.length > 1) {
    errors.push(
      `${accepted.length} designations are accepted (${accepted.map((d) => d.id).join(", ")}): choose one with SP1_DESIGNATION_ID`,
    );
    return null;
  }
  const why = compatible
    .map((d) => {
      const h = halts.haltsOfIdentity(d.identity)[0];
      return `${d.id}: identity recorded HALTED (fact #${h.seq}, chain ${h.chainId}, ${h.reason})`;
    })
    .join("; ");
  errors.push(`no accepted designation for the recorded wrapper build${why === "" ? "" : ` (${why})`}`);
  return null;
}

/** The deployment plan, or a refusal naming every reason, before any transaction. */
export function planWrapperDeployment(input: PlanInput): WrapperDeploymentPlan {
  const { chainId, env } = input;
  const mainnet = FORBIDDEN_MAINNET_CHAIN_IDS.get(chainId);
  if (mainnet !== undefined) {
    throw new Error(
      `REFUSING TO DEPLOY: chain ${chainId} is ${mainnet}, a MAINNET; the prototype is testnet/local only`,
    );
  }
  const local = isLocal(chainId);
  const mock = local && env.ALLOW_MOCK_SP1 === "true";
  const errors: string[] = [];
  if (!local) {
    for (const key of ["SP1_VERIFIER_ADDRESS", "PROGRAM_VKEY"]) {
      if (env[key] !== undefined && env[key] !== "") {
        errors.push(
          `no override exists on chain ${chainId}: ${key} is set, but the SP1 verifier and PROGRAM_VKEY come only from a designation`,
        );
      }
    }
    if (env.ALLOW_MOCK_SP1 === "true")
      errors.push(`no override exists on chain ${chainId}: ALLOW_MOCK_SP1 is local-only`);
  } else if (!mock && env.PROGRAM_VKEY !== undefined && env.PROGRAM_VKEY !== "") {
    errors.push(
      "PROGRAM_VKEY is a local test override: it needs ALLOW_MOCK_SP1=true, and then nothing it deploys is designated",
    );
  }
  if (input.currentBuildErrors.length > 0) {
    errors.push(
      `the compiled ZKMLDSAVerifier is not the latest recorded build: ${input.currentBuildErrors.join("; ")}`,
    );
  }
  const build = input.builds[input.builds.length - 1];
  if (!build) errors.push("no wrapper build is recorded");

  let haltPrincipal: string | null = null;
  try {
    haltPrincipal = resolveHaltPrincipal(env.HALT_PRINCIPAL_ADDRESS, local, input.localHaltPrincipal);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }
  if (haltPrincipal !== null && haltPrincipal === getAddress(input.deployer)) {
    errors.push(
      "the halt principal must not be the deployer: the deployer usually deploys and owns the consumers, and a halt principal never governs one",
    );
  }

  let designation: ProgramDesignation | null = null;
  let programVKey = TEST_ONLY_MOCK_VKEY;
  if (mock) {
    const override = env.PROGRAM_VKEY;
    if (override !== undefined && override !== "") {
      if (!isHexString(override, 32) || override === ZeroHash)
        errors.push("PROGRAM_VKEY must be a non-zero bytes32 value");
      else programVKey = override;
    }
  } else {
    designation = chooseDesignation(input, build, errors);
    if (designation !== null && build) {
      if (compatibleDesignations(build, [designation]).length === 0) {
        errors.push(`wrapper build ${build.id} pins another SP1 verifier than designation ${designation.id}'s`);
      }
      const halts = registryState(input.registry).haltsOfIdentity(designation.identity);
      if (halts.length > 0) {
        errors.push(
          `designation ${designation.id}'s identity is recorded HALTED (fact #${halts[0].seq}, chain ${halts[0].chainId}, ` +
            `${halts[0].reason}): deploy a successor's identity instead`,
        );
      }
      programVKey = designation.programVKey;
    }
  }
  if (errors.length > 0 || !build || haltPrincipal === null) {
    throw new Error(`refusing to deploy ZKMLDSAVerifier on chain ${chainId}:\n - ${errors.join("\n - ")}`);
  }
  const localVerifier = local && env.SP1_VERIFIER_ADDRESS ? getAddress(env.SP1_VERIFIER_ADDRESS) : null;
  return {
    chainId,
    mode: mock ? "LOCAL_TEST_MOCK" : local ? "LOCAL_DESIGNATED" : "DESIGNATED",
    designation,
    build,
    sp1Verifier: local ? localVerifier : (designation as ProgramDesignation).verifier.address,
    expectedSp1CodeKeccak: build.pins.sp1VerifierCodehash,
    programVKey,
    haltPrincipal,
  };
}

/**
 * On the target chain, read-only: the SP1 verifier runs the designated code and gives the required verdicts there, and
 * the canary's positive control fires on `devProvider` (an in-process EVM). Throws on any refusal or RPC failure.
 *
 * Every read is at one finalized block, fetched once (review finding L-6): a lagging or reorganizing backend cannot
 * mix states, and a chain or RPC that names no finalized block stops the deployment (never the latest block instead).
 * It reads one provider, the deployment's own, and trusts what it reports: a lying RPC is not refused here (AUTH-6);
 * the committed per-chain observation reads two agreeing providers.
 */
export async function preDeploymentChecks(
  provider: Provider,
  plan: WrapperDeploymentPlan,
  devProvider: DevProvider,
): Promise<{
  codeKeccak: string;
  finalizedBlock: number;
  executionPass: true;
  verdicts: Verdicts;
  canaryDetects: true;
}> {
  if (plan.designation === null || plan.sp1Verifier === null) {
    throw new Error("only a designated deployment with its SP1 verifier in place is checked");
  }
  const at = await finalizedBlock(provider);
  const code = await provider.getCode(plan.sp1Verifier, at.block);
  const codeKeccak = code === "0x" ? null : keccak256(code);
  if (codeKeccak !== plan.expectedSp1CodeKeccak) {
    throw new Error(
      `the SP1 verifier at ${plan.sp1Verifier} runs ${codeKeccak ?? "no code"}, not the designated code ${plan.expectedSp1CodeKeccak}`,
    );
  }
  const designed = chainExecutionCalls(plan.designation);
  const sp1 = plan.sp1Verifier;
  const calls = {
    real: { ...designed.real, to: sp1 },
    tampered: { ...designed.tampered, to: sp1 },
    canary: { ...designed.canary, to: sp1 },
  };
  const result = await runChainExecutionCheck(provider, calls, at.block);
  if (!result.pass) throw new Error(`the per-chain execution check failed: ${result.failures.join("; ")}`);
  const control = await canaryPositiveControl(devProvider, calls.canary.data, plan.expectedSp1CodeKeccak);
  if (!control.detects) {
    throw new Error(
      `the canary's positive control did not fire (${JSON.stringify(control)}): the check proves nothing`,
    );
  }
  return { codeKeccak, finalizedBlock: at.block, executionPass: true, verdicts: result.verdicts, canaryDetects: true };
}

/** The subset of Hardhat's `ethers` a deployment needs. */
export interface DeployingEthers {
  provider: Provider & { send(method: string, params: unknown[]): Promise<unknown> };
  getContractFactory: (name: string, signer: Signer) => Promise<{ deploy: (...args: unknown[]) => Promise<any> }>;
}

/**
 * Deploys the planned wrapper; on a local chain first the designated verifier's real bytes (from their CREATE2-
 * authenticated initcode) when the plan names no verifier. On the local test path, the mock replaces that code after
 * the wrapper's constructor checked it. Returns the wrapper and the plan with its SP1 verifier filled in.
 */
export async function deployPlannedWrapper(
  ethers: DeployingEthers,
  deployer: Signer,
  plan: WrapperDeploymentPlan,
  repoRoot = ".",
): Promise<{ wrapper: string; plan: WrapperDeploymentPlan }> {
  let sp1 = plan.sp1Verifier;
  if (sp1 === null) {
    if (plan.mode === "DESIGNATED") throw new Error("a designated deployment names its SP1 verifier");
    const initcode = JSON.parse(readFileSync(resolve(repoRoot, VERIFIER_BYTECODE_REL), "utf8")).deployments["v6.1.0"]
      .initcode;
    const receipt = await (await deployer.sendTransaction({ data: initcode })).wait();
    sp1 = getAddress(String(receipt?.contractAddress));
  }
  const factory = await ethers.getContractFactory("ZKMLDSAVerifier", deployer);
  const contract = await factory.deploy(sp1, plan.programVKey, plan.haltPrincipal);
  await contract.waitForDeployment();
  if (plan.mode === "LOCAL_TEST_MOCK") {
    const mock = await (await ethers.getContractFactory("MockSP1Verifier", deployer)).deploy();
    await mock.waitForDeployment();
    await ethers.provider.send("hardhat_setCode", [sp1, await ethers.provider.getCode(await mock.getAddress())]);
    // MockSP1Verifier.shouldSucceed (slot 0) is set by its constructor, which never ran at this address.
    await ethers.provider.send("hardhat_setStorageAt", [sp1, "0x0", `0x${"0".repeat(63)}1`]);
  }
  return { wrapper: getAddress(await contract.getAddress()), plan: { ...plan, sp1Verifier: sp1 } };
}

/** How the deployed wrapper departs from the plan, measured from the chain; empty when it is exactly what was planned. */
export async function readBackErrors(
  provider: Provider,
  wrapper: string,
  plan: WrapperDeploymentPlan,
  builds: readonly WrapperBuild[],
): Promise<string[]> {
  const p = await profileVerifier(provider, wrapper, builds);
  const errors: string[] = [];
  if (p.wrapperBuild !== plan.build.id) {
    errors.push(
      `${wrapper} is not the recorded build ${plan.build.id} (it runs ${p.wrapperBuild ?? "no recorded build"})`,
    );
  }
  if (plan.sp1Verifier === null || p.sp1Verifier !== getAddress(plan.sp1Verifier)) {
    errors.push(`its SP1 verifier is ${String(p.sp1Verifier)}, not ${String(plan.sp1Verifier)}`);
  }
  if (p.programVKey !== plan.programVKey)
    errors.push(`its PROGRAM_VKEY is ${String(p.programVKey)}, not ${plan.programVKey}`);
  if (p.haltPrincipal !== getAddress(plan.haltPrincipal)) {
    errors.push(`its halt principal is ${String(p.haltPrincipal)}, not ${plan.haltPrincipal}`);
  }
  if (p.halted !== false) errors.push(`it is not ACTIVE (halted: ${String(p.halted)})`);
  if (plan.mode !== "LOCAL_TEST_MOCK") {
    if (p.sp1VerifierCodeKeccak !== plan.expectedSp1CodeKeccak) {
      errors.push(`its SP1 verifier runs ${String(p.sp1VerifierCodeKeccak)}, not the designated code`);
    }
    if (plan.designation !== null && p.identity !== plan.designation.identity) {
      errors.push(`its identity ${String(p.identity)} is not designation ${plan.designation.id}'s`);
    }
  }
  return errors;
}
