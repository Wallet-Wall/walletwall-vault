/**
 * EXPERIMENTAL PROTOTYPE — per-fix byte attribution for the authority-closure
 * remediation. DIAGNOSTIC ONLY.
 *
 * Each variant ABLATES exactly one security correction from the current source
 * and recompiles, so the reported delta is that correction's cost. The ablated
 * variants are NOT candidates — every one of them reintroduces a defect that
 * was reproduced against the real kernel. Nothing here is ever deployed, and no
 * T0/T1 invariant is deleted to recover bytes.
 *
 * Run:  npx tsx prototype/vnext-kernel/deltas.ts
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SRC = path.join("prototype", "vnext-kernel", "contracts");
const KERNEL = path.join(SRC, "VaultKernelPrototype.sol");
const OZ = "5.6.1";

function solcPath(): string {
  const base = path.join(os.homedir(), "AppData", "Local", "hardhat-nodejs", "Cache", "compilers-v3", "windows-amd64");
  const hit = fs.readdirSync(base).find((f) => f.includes("0.8.24") && f.endsWith(".exe"));
  if (hit === undefined) throw new Error("pinned solc 0.8.24 not found");
  return path.join(base, hit);
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
          `npm/@openzeppelin/contracts@${OZ}/${spec.slice("@openzeppelin/contracts/".length)}`,
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

function runtimeBytes(kernelSrc: string): number {
  const input = {
    language: "Solidity",
    sources: sources(kernelSrc),
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      remappings: [`project/:@openzeppelin/contracts/=npm/@openzeppelin/contracts@${OZ}/`],
      outputSelection: { "*": { "*": ["evm.deployedBytecode.object"] } },
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
  return out.contracts[file].VaultKernelPrototype.evm.deployedBytecode.object.length / 2;
}

/** One ablation: a list of exact source substitutions that remove a fix. */
interface Ablation {
  readonly label: string;
  readonly edits: readonly (readonly [string, string])[];
}

const ABLATIONS: readonly Ablation[] = [
  {
    label: "A  HYBRID governance (rotate / setVerifier / setPolicy)",
    edits: [
      // Revert the three governance paths to the ECDSA-only gate that findings
      // A1 and A2 exploited.
      [
        "        _authorise(digest, ecdsaSig, pqSig, pqKey);\n        _requireIncomingPossession(",
        "        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();\n        _requireIncomingPossession(",
      ],
      [
        "        _authorise(digest, ecdsaSig, pqSig, pqKey);\n        _requireNoDowngrade(floor);",
        "        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();\n        _requireNoDowngrade(floor);",
      ],
      [
        "        _authorise(digest, ecdsaSig, pqSig, pqKey);\n        _consume(DOMAIN_CREDENTIAL, nonce, deadline);\n        policyEngine = policy;",
        "        if (!_floorAuthorises(digest, ecdsaSig)) revert BadSignature();\n        _consume(DOMAIN_CREDENTIAL, nonce, deadline);\n        policyEngine = policy;",
      ],
    ],
  },
  {
    label: "B  guardian principal distinctness (canonical roster)",
    edits: [
      ["        _requireCanonicalRoster(guardianThreshold, p.members, p.isContract);\n", ""],
      [
        "        _requireCanonicalRoster(newThreshold, newMembers, newIsContract);",
        "        if (newThreshold == 0 || newMembers.length < newThreshold) revert BadRoster();",
      ],
      [
        "        _requireCanonicalRoster(g.threshold, g.guardians, g.guardianIsContract);",
        "        if (g.threshold == 0 || g.guardians.length < g.threshold) revert BadRoster();",
      ],
    ],
  },
  {
    label: "D  incoming credential possession (PoP)",
    edits: [
      [
        `        _requireIncomingPossession(
            credentialPossessionDigest(c.newSigner, c.newPqKeyHash),
            c.newSigner,
            c.newPqKeyHash,
            pqVerifier,
            c
        );
`,
        "",
      ],
      [
        `        _requireIncomingPossession(
            recoveryPossessionDigest(),
            r.proposedSigner,
            r.proposedPqKeyHash,
            r.proposedVerifier,
            c
        );

`,
        "",
      ],
    ],
  },
  {
    label: "E  genesis validation + effectiveSafeState + verifier code checks",
    edits: [
      ["        if (g.verifier.code.length == 0) revert ZeroAddress();\n", ""],
      ["        _requireSaneFloor(g.floor);\n", ""],
      ["        if (g.floor.requirePq && g.pqKeyHash == bytes32(0)) revert BadSignature();\n", ""],
      ["        if (verifier.code.length == 0) revert ZeroAddress();\n", ""],
      ["        _requireSaneFloor(floor);\n", ""],
      ["        if (proposedVerifier.code.length == 0) revert ZeroAddress();\n", ""],
    ],
  },
];

function main(): void {
  const full = fs.readFileSync(KERNEL, "utf8");
  const base = runtimeBytes(full);
  console.log("Per-fix byte attribution — DIAGNOSTIC. Ablated variants are NOT candidates.");
  console.log(`solc 0.8.24, cancun, optimizer 200, viaIR off.\n`);
  console.log(`BEFORE remediation (head 79e05a34)            14,339`);
  console.log(`AFTER  remediation (this head)                ${base.toLocaleString("en-US").padStart(6)}`);
  console.log(`TOTAL delta                                   ${(base - 14339 >= 0 ? "+" : "") + (base - 14339)}\n`);
  console.log("ablation                                        without    cost");
  let attributed = 0;
  for (const a of ABLATIONS) {
    let src = full;
    for (const [from, to] of a.edits) {
      if (!src.includes(from)) throw new Error(`${a.label}: anchor drifted -> ${from.slice(0, 60)}`);
      src = src.split(from).join(to);
    }
    const without = runtimeBytes(src);
    const cost = base - without;
    attributed += cost;
    console.log(`${a.label.padEnd(46)} ${without.toLocaleString("en-US").padStart(7)}  ${("+" + cost).padStart(6)}`);
  }
  console.log(
    `\nattributed ${attributed}; residual ${base - 14339 - attributed} (finding C lives in the FACTORY, ` +
      `plus optimizer interaction between overlapping ablations).`,
  );
}

main();
