/**
 * EXPERIMENTAL PROTOTYPE — incremental byte decomposition (K0..K6).
 *
 * DIAGNOSTIC ONLY. These variants are NOT candidate kernels: each one is the
 * full kernel with later responsibilities ABLATED, compiled solely to attribute
 * bytes to responsibilities. The only shippable object is K6, which contains
 * every KERNEL row of KERNEL_ADMISSION.md. No security predicate is ever
 * deleted to improve a size result.
 *
 * WHAT THE DELTAS DO AND DO NOT MEASURE. Public storage variables — and the
 * getters solc generates for them — are held CONSTANT across every level, so a
 * delta is the cost of LOGIC, never of accessors. The storage layout is
 * therefore identical at every level and only function bodies vary.
 *
 * Run:  npx tsx prototype/vnext-kernel/decompose.ts
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SRC = path.join("prototype", "vnext-kernel", "contracts");
const KERNEL = path.join(SRC, "VaultKernelPrototype.sol");
const OZ_VERSION = "5.6.1";

/** Which level first introduces each function. Level 0 is always present. */
const LEVELS: Record<string, number> = {
  // K1 — execution, the kernel-evaluated floor, replay state
  execute: 1,
  _floorAuthorises: 1,
  _authorise: 1,
  _consume: 1,
  _digest: 1,
  // K2 — guardian authority (commitment, threshold, generation, quorum)
  rosterCommitment: 2,
  setGuardians: 2,
  _requireQuorum: 2,
  _attests: 2,
  // K3 — recovery
  initiateRecovery: 3,
  cancelRecovery: 3,
  // K-9 mechanism B (W2) arrives with recovery, alongside the credential half.
  cancelRecoveryByQuorum: 3,
  executeRecovery: 3,
  _requireRecoveryOpen: 3,
  // Effective liveness is read by initiateRecovery / both cancellations (K3) and
  // by bindMigration (K5), so it must exist from K3 onward.
  _recoveryIsLive: 3,
  // Recovery INSTALLS a credential, so the installer arrives with recovery
  // rather than with the voluntary rotation entry point in K6. Placing it later
  // does not compile — a useful reminder that the layering is a dependency
  // fact, not a presentational choice.
  _installCredential: 3,
  // K4 — the full safe-state machine (containment budget / window / expiry)
  enterContainment: 4,
  // K5 — migration
  bindMigration: 5,
  retire: 5,
  egress: 5,
  _balanceOf: 5,
  // K6 — credential rotation and plane governance
  rotateCredential: 6,
  setVerifier: 6,
  setPolicy: 6,
  _requireNoDowngrade: 6,
};

const LABELS = [
  "K0  identity + initialization",
  "K1  + execution / floor auth / replay",
  "K2  + guardian commitment + quorum",
  "K3  + recovery",
  "K4  + full safe-state machine",
  "K5  + migration",
  "K6  + rotation, plane governance, no-downgrade  [FULL CANDIDATE]",
];

function solcPath(): string {
  const base = path.join(os.homedir(), "AppData", "Local", "hardhat-nodejs", "Cache", "compilers-v3", "windows-amd64");
  const hit = fs.readdirSync(base).find((f) => f.includes("0.8.24") && f.endsWith(".exe"));
  if (hit === undefined) throw new Error("pinned solc 0.8.24 not found");
  return path.join(base, hit);
}

/** Remove one `    function NAME(...) { ... }` block, braces matched. */
function removeFunction(src: string, name: string): string {
  const re = new RegExp(`\\n    function ${name}\\s*\\(`);
  const m = re.exec(src);
  if (m === null) throw new Error(`function ${name} not found`);
  let i = src.indexOf("{", m.index + m[0].length);
  if (i === -1) throw new Error(`no body for ${name}`);
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  return src.slice(0, m.index) + src.slice(i + 1);
}

/**
 * At levels below K4 the containment machinery is absent, so the state gate
 * collapses to a plain equality on the stored state. Substituting it keeps the
 * ablation honest: K4's delta is then the containment BUDGET and EXPIRY logic,
 * not the existence of a state check that K1 already needed.
 */
const FULL_EFFECTIVE = `    function _effectiveState() internal view returns (SafeState) {
        // Containment self-expires on WALL CLOCK with NO principal acting.
        if (safeState == SafeState.CONTAINED && block.timestamp >= containedUntil) return SafeState.NORMAL;
        return safeState;
    }`;
const SIMPLE_EFFECTIVE = `    function _effectiveState() internal view returns (SafeState) {
        return safeState;
    }`;

function variant(level: number): string {
  let src = fs.readFileSync(KERNEL, "utf8");
  const drop = Object.entries(LEVELS)
    .filter(([, lv]) => lv > level)
    .map(([n]) => n);
  for (const n of drop) src = removeFunction(src, n);
  if (level < 4) {
    if (!src.includes(FULL_EFFECTIVE)) throw new Error("_effectiveState anchor drifted");
    src = src.replace(FULL_EFFECTIVE, SIMPLE_EFFECTIVE);
  }
  return src;
}

function sources(kernelSrc: string): Record<string, { content: string }> {
  const out: Record<string, { content: string }> = {};
  const seen = new Set<string>();
  const posix = (p: string) => p.split(path.sep).join("/");
  const visit = (key: string, disk: string, override?: string): void => {
    if (seen.has(key)) return;
    seen.add(key);
    const content = override ?? fs.readFileSync(disk, "utf8");
    out[key] = { content };
    for (const m of content.matchAll(/import\s+(?:\{[^}]*\}\s+from\s+)?"([^"]+)"/g)) {
      const spec = m[1];
      if (spec.startsWith("@openzeppelin/contracts/")) {
        visit(
          `npm/@openzeppelin/contracts@${OZ_VERSION}/${spec.slice("@openzeppelin/contracts/".length)}`,
          path.join("node_modules", spec),
        );
      } else {
        visit(
          path.posix.normalize(path.posix.join(path.posix.dirname(key), spec)),
          path.normalize(path.join(path.dirname(disk), spec)),
        );
      }
    }
  };
  visit(`project/${posix(SRC)}/VaultKernelPrototype.sol`, KERNEL, kernelSrc);
  return out;
}

function compile(kernelSrc: string): { runtime: number; initcode: number; selectors: number; externalCalls: number } {
  const input = {
    language: "Solidity",
    sources: sources(kernelSrc),
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      remappings: [`project/:@openzeppelin/contracts/=npm/@openzeppelin/contracts@${OZ_VERSION}/`],
      outputSelection: {
        "*": { "*": ["evm.bytecode.object", "evm.deployedBytecode.object", "evm.methodIdentifiers"] },
      },
    },
  };
  const out = JSON.parse(
    execFileSync(solcPath(), ["--standard-json"], {
      input: JSON.stringify(input),
      maxBuffer: 256 * 1024 * 1024,
    }).toString(),
  );
  const fatal = (out.errors ?? []).filter((e: { severity: string }) => e.severity === "error");
  if (fatal.length > 0) throw new Error(fatal.map((e: { formattedMessage: string }) => e.formattedMessage).join("\n"));
  const file = Object.keys(out.contracts).find((k) => k.includes("VaultKernelPrototype.sol"))!;
  const c = out.contracts[file].VaultKernelPrototype;
  const externalCalls =
    (kernelSrc.match(/\.call\{/g) ?? []).length +
    (kernelSrc.match(/\.call\(/g) ?? []).length +
    (kernelSrc.match(/staticcall/g) ?? []).length +
    (kernelSrc.match(/\.recover\(/g) ?? []).length;
  return {
    runtime: c.evm.deployedBytecode.object.length / 2,
    initcode: c.evm.bytecode.object.length / 2,
    selectors: Object.keys(c.evm.methodIdentifiers).length,
    externalCalls,
  };
}

function main(): void {
  console.log("K0..K6 byte decomposition — DIAGNOSTIC ONLY. Only K6 is a candidate kernel.");
  console.log("solc 0.8.24, cancun, optimizer 200, viaIR off. Storage/getters held constant.\n");
  console.log("level                                                        runtime   delta  initcode  sel  extcalls");
  let prev = 0;
  for (let level = 0; level <= 6; level++) {
    const r = compile(variant(level));
    const delta = level === 0 ? r.runtime : r.runtime - prev;
    prev = r.runtime;
    console.log(
      `${LABELS[level].padEnd(58)} ${String(r.runtime).padStart(7)} ${String(level === 0 ? "" : (delta >= 0 ? "+" : "") + delta).padStart(7)} ${String(r.initcode).padStart(9)} ${String(r.selectors).padStart(4)} ${String(r.externalCalls).padStart(9)}`,
    );
  }
}

main();
