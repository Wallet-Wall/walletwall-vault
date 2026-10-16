/**
 * SP1 implementation lane: the wrapper registry as an append-only fact log with build provenance (closes SP1-TD2
 * review residual R2-3; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD2's registry was a list of (chain, address). It now records, as facts appended in order, each wrapper's
 * registration — chain, address, the wrapper build it was deployed from, the designation it serves, the SP1 verifier's
 * runtime code hash, PROGRAM_VKEY, the identity, the halt principal, the deployment — and each halt. Nothing is ever
 * deleted or rewritten: CI walks the registry's whole git history (every commit that changed it, against every parent,
 * and the working tree against HEAD) and refuses any change that is not a pure append. "The current JSON looks okay"
 * is not the proof; the history is.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import { readDesignations, type ProgramDesignation } from "../scripts/lib/sp1-designation";
import { readWrapperBuilds, type WrapperBuild } from "../scripts/lib/sp1-wrapper-build";
import {
  REGISTRY_REL,
  REGISTRY_SCHEMA,
  HALT_REASONS,
  readRegistry,
  registryErrors,
  registryExtensionErrors,
  registryState,
  validateRegistryInRepo,
  type RegistryDoc,
  type RegistryFact,
} from "../scripts/lib/sp1-registry";
import { directoryHistoryErrors, fileHistoryErrors } from "../scripts/lib/append-only-history";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const SEPOLIA = "11155111";
const BASE_SEPOLIA = "84532";
const addr = (label: string) => ethers.getAddress(ethers.dataSlice(ethers.id(label), 12));
const tx = (label: string) => ethers.id(`tx: ${label}`);

describe("SP1 implementation lane — the wrapper registry", function () {
  let builds: WrapperBuild[];
  let designations: ProgramDesignation[];
  let d1: ProgramDesignation;
  let b1: WrapperBuild;

  const registration = (seq: number, chainId: string, label: string, extra: Partial<RegistryFact> = {}) =>
    ({
      seq,
      kind: "WRAPPER_REGISTERED",
      chainId,
      address: addr(`wrapper ${label}`),
      wrapperBuild: b1.id,
      designation: d1.id,
      sp1Verifier: { address: d1.verifier.address, runtimeCodeKeccak: d1.verifier.runtimeCodeKeccak },
      programVKey: d1.programVKey,
      identity: d1.identity,
      haltPrincipal: addr(`halt principal ${label}`),
      deployment: { txHash: tx(label), block: 1000 + seq, deployer: addr(`deployer ${label}`) },
      observedAt: { block: 1010 + seq, blockHash: ethers.id(`block ${label}`) },
      replaces: null,
      ...extra,
    }) as RegistryFact;
  const halt = (seq: number, chainId: string, label: string, extra: Partial<RegistryFact> = {}) =>
    ({
      seq,
      kind: "WRAPPER_HALTED",
      chainId,
      address: addr(`wrapper ${label}`),
      identity: d1.identity,
      reason: "VERIFIER_SOUNDNESS",
      halt: { txHash: tx(`halt ${label}`), block: 2000 + seq },
      observedAt: { block: 2010 + seq, blockHash: ethers.id(`halt block ${label}`) },
      ...extra,
    }) as RegistryFact;
  const doc = (facts: RegistryFact[]): RegistryDoc => ({
    schema: REGISTRY_SCHEMA,
    note: "test",
    migratedFrom: { schema: "walletwall.sp1-wrapper-registry.v1", entries: 0 },
    facts,
  });

  before(function () {
    builds = readWrapperBuilds(".");
    designations = readDesignations(".");
    d1 = designations[0];
    b1 = builds[0];
  });

  describe("what a fact records", function () {
    it("the committed registry is the v2 fact log, migrated from SP1-TD2's empty list, with no wrapper yet", function () {
      const committed = readRegistry(".");
      expect(committed.schema).to.equal(REGISTRY_SCHEMA);
      expect(committed.migratedFrom).to.deep.equal({ schema: "walletwall.sp1-wrapper-registry.v1", entries: 0 });
      expect(committed.facts).to.deep.equal([]);
      expect(validateRegistryInRepo(".")).to.deep.equal([]);
      expect(REGISTRY_REL).to.equal("evidence/zk/sp1-td2/wrapper-registry.json");
    });

    it("a registration and a halt that bind build, designation, verifier code, vkey, identity and principal pass", function () {
      const facts = [registration(1, SEPOLIA, "a"), registration(2, BASE_SEPOLIA, "b"), halt(3, SEPOLIA, "a")];
      expect(registryErrors(doc(facts), builds, designations)).to.deep.equal([]);
    });

    const refused: [string, () => RegistryFact[], RegExp][] = [
      [
        "an unrecorded wrapper build",
        () => [registration(1, SEPOLIA, "a", { wrapperBuild: "zkmldsa-verifier-b9" })],
        /wrapper build/,
      ],
      [
        "an unknown designation",
        () => [registration(1, SEPOLIA, "a", { designation: "mldsa65-withdrawal-d9" })],
        /designation/,
      ],
      [
        "a vkey that is not the designation's",
        () => [registration(1, SEPOLIA, "a", { programVKey: "0x" + "12".repeat(32) })],
        /identity|vkey/,
      ],
      [
        "verifier code that is not the designation's",
        () => [
          registration(1, SEPOLIA, "a", {
            sp1Verifier: { address: d1.verifier.address, runtimeCodeKeccak: ethers.ZeroHash },
          }),
        ],
        /verifier/,
      ],
      [
        "a stated identity that is not the formula's",
        () => [registration(1, SEPOLIA, "a", { identity: ethers.ZeroHash })],
        /identity/,
      ],
      [
        "the same wrapper twice",
        () => [registration(1, SEPOLIA, "a"), registration(2, SEPOLIA, "a")],
        /already registered/,
      ],
      ["a gap in the sequence", () => [registration(2, SEPOLIA, "a")], /seq/],
      ["a halt of an unregistered wrapper", () => [halt(1, SEPOLIA, "a")], /not registered/],
      [
        "a halt recorded twice",
        () => [registration(1, SEPOLIA, "a"), halt(2, SEPOLIA, "a"), halt(3, SEPOLIA, "a")],
        /twice/,
      ],
      [
        "a halt without a known reason",
        () => [registration(1, SEPOLIA, "a"), halt(2, SEPOLIA, "a", { reason: "BECAUSE" } as any)],
        /reason/,
      ],
      [
        "a halt whose identity is not the wrapper's",
        () => [registration(1, SEPOLIA, "a"), halt(2, SEPOLIA, "a", { identity: ethers.ZeroHash })],
        /identity/,
      ],
      [
        "a lowercase (unchecked) address",
        () => [registration(1, SEPOLIA, "a", { address: addr("wrapper a").toLowerCase() })],
        /checksum/,
      ],
      [
        "a zero halt principal",
        () => [registration(1, SEPOLIA, "a", { haltPrincipal: ethers.ZeroAddress })],
        /halt principal/,
      ],
      ["a chain id that is not decimal", () => [registration(1, "0xaa36a7", "a")], /chain/],
      [
        "registering an identity halted on another chain (cross-chain halted identity)",
        () => [registration(1, SEPOLIA, "a"), halt(2, SEPOLIA, "a"), registration(3, BASE_SEPOLIA, "b")],
        /halted .* on chain 11155111/,
      ],
      [
        "a replacement that names no earlier wrapper on its chain",
        () => [registration(1, SEPOLIA, "a", { replaces: { address: addr("nobody") } })],
        /replaces/,
      ],
    ];
    for (const [label, facts, rule] of refused) {
      it(`refuses ${label}`, function () {
        expect(registryErrors(doc(facts()), builds, designations).join("\n")).to.match(rule);
      });
    }

    it("the state it publishes: per-chain registrations, and every halted identity on every chain", function () {
      const facts = [registration(1, SEPOLIA, "a"), registration(2, BASE_SEPOLIA, "b"), halt(3, SEPOLIA, "a")];
      const state = registryState(doc(facts));
      expect(state.registeredOn(SEPOLIA)).to.deep.equal([addr("wrapper a")]);
      expect(state.registeredOn(BASE_SEPOLIA)).to.deep.equal([addr("wrapper b")]);
      expect(state.registeredOn("1")).to.deep.equal([]);
      expect(state.recordedHalted(SEPOLIA, addr("wrapper a"))).to.equal(true);
      expect(state.recordedHalted(BASE_SEPOLIA, addr("wrapper b"))).to.equal(false);
      expect(state.haltsOfIdentity(d1.identity)).to.deep.equal([
        { chainId: SEPOLIA, address: addr("wrapper a"), seq: 3, reason: "VERIFIER_SOUNDNESS" },
      ]);
      expect(state.haltsOfIdentity(ethers.ZeroHash)).to.deep.equal([]);
      expect(HALT_REASONS).to.include("VERIFIER_SOUNDNESS");
    });
  });

  describe("append-only, proved from the git history", function () {
    let dir: string;
    const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, encoding: "utf8" }).trim();
    const write = (rel: string, content: string) => {
      mkdirSync(dirname(join(dir, rel)), { recursive: true });
      writeFileSync(join(dir, rel), content);
    };
    const commit = (message: string) => {
      git("add", "-A");
      git("commit", "-q", "--allow-empty", "-m", message);
      return git("rev-parse", "HEAD");
    };
    const put = (facts: RegistryFact[], message: string) => {
      write(REGISTRY_REL, `${JSON.stringify(doc(facts), null, 2)}\n`);
      return commit(message);
    };
    const v1 = (entries: unknown[]) =>
      `${JSON.stringify({ schema: "walletwall.sp1-wrapper-registry.v1", note: "td2", entries }, null, 2)}\n`;
    const history = () => fileHistoryErrors(dir, REGISTRY_REL, registryExtensionErrors);

    beforeEach(function () {
      dir = mkdtempSync(join(tmpdir(), "sp1-registry-history-"));
      git("init", "-q", "-b", "main");
      git("config", "user.email", "test@example.invalid");
      git("config", "user.name", "test");
      git("config", "core.autocrlf", "false");
      write(REGISTRY_REL, v1([]));
      commit("SP1-TD2: empty v1 registry");
    });
    afterEach(function () {
      rmSync(dir, { recursive: true, force: true });
    });

    it("appends pass: v1 empty → v2 → one fact → two facts → a halt", function () {
      put([], "migrate");
      put([registration(1, SEPOLIA, "a")], "register a");
      put([registration(1, SEPOLIA, "a"), registration(2, BASE_SEPOLIA, "b")], "register b");
      put([registration(1, SEPOLIA, "a"), registration(2, BASE_SEPOLIA, "b"), halt(3, SEPOLIA, "a")], "halt a");
      expect(history()).to.deep.equal([]);
    });

    const destructive: [string, RegistryFact[][], RegExp][] = [
      ["deleting a fact", [[], [], []], /removed or rewrote/],
      ["rewriting a field", [[], [], []], /removed or rewrote/],
      ["reordering facts", [[], [], []], /removed or rewrote/],
      ["deleting a halt (the identity looks un-halted again)", [[], [], []], /removed or rewrote/],
    ];
    destructive.forEach(([label], i) => {
      it(`refuses ${label}, naming the commit`, function () {
        const a = registration(1, SEPOLIA, "a");
        const b = registration(2, BASE_SEPOLIA, "b");
        put([a, b], "two facts");
        const after: RegistryFact[][] = [
          [a],
          [a, { ...b, programVKey: "0x" + "34".repeat(32) }],
          [
            { ...b, seq: 1 },
            { ...a, seq: 2 },
          ],
          [],
        ];
        if (i === 3) put([a, b, halt(3, SEPOLIA, "a")], "halt a");
        const bad = put(i === 3 ? [a, b] : after[i], `destructive: ${label}`);
        const errors = history().join("\n");
        expect(errors, label).to.match(destructive[i][2]);
        expect(errors, label).to.include(bad.slice(0, 12));
      });
    });

    it("refuses a downgrade to v1, a migration of a non-empty v1, and deleting the registry", function () {
      put([registration(1, SEPOLIA, "a")], "v2");
      write(REGISTRY_REL, v1([]));
      const downgrade = commit("downgrade");
      expect(history().join("\n")).to.include(downgrade.slice(0, 12));
      rmSync(dir, { recursive: true, force: true });

      dir = mkdtempSync(join(tmpdir(), "sp1-registry-history-"));
      git("init", "-q", "-b", "main");
      git("config", "user.email", "test@example.invalid");
      git("config", "user.name", "test");
      write(REGISTRY_REL, v1([{ chainId: SEPOLIA, address: addr("wrapper old") }]));
      commit("v1 with an entry");
      const migrate = put([], "migration that drops the v1 entry");
      expect(history().join("\n")).to.match(/non-empty v1/);
      expect(history().join("\n")).to.include(migrate.slice(0, 12));

      git("rm", "-q", REGISTRY_REL);
      const removal = commit("delete the registry");
      expect(history().join("\n")).to.include(removal.slice(0, 12));
      expect(history().join("\n")).to.match(/deleted/);
    });

    it("refuses a rewrite made on a side branch and merged, and a merge that resolves by dropping a fact", function () {
      const a = registration(1, SEPOLIA, "a");
      const b = registration(2, BASE_SEPOLIA, "b");
      put([a], "main: a");
      git("checkout", "-q", "-b", "side");
      const sideRewrite = put([{ ...a, haltPrincipal: addr("someone else") }], "side: rewrite a");
      git("checkout", "-q", "main");
      git("merge", "-q", "--no-ff", "-m", "merge side", "side");
      expect(history().join("\n")).to.include(sideRewrite.slice(0, 12));

      rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), "sp1-registry-history-"));
      git("init", "-q", "-b", "main");
      git("config", "user.email", "test@example.invalid");
      git("config", "user.name", "test");
      put([a], "main: a");
      git("checkout", "-q", "-b", "side");
      put([a, b], "side: b");
      git("checkout", "-q", "main");
      put([a, halt(2, SEPOLIA, "a")], "main: halt a");
      try {
        git("merge", "-q", "-m", "merge", "side");
      } catch {
        // conflict: resolve by taking the side's list, which drops main's halt
      }
      write(REGISTRY_REL, `${JSON.stringify(doc([a, b]), null, 2)}\n`);
      const merge = commit("merge: resolve by dropping the halt");
      expect(git("rev-list", "--parents", "-n", "1", "HEAD").split(" ").length).to.equal(3);
      expect(history().join("\n")).to.include(merge.slice(0, 12));
    });

    it("refuses an uncommitted destructive edit in the working tree", function () {
      put([registration(1, SEPOLIA, "a")], "a");
      write(REGISTRY_REL, `${JSON.stringify(doc([]), null, 2)}\n`);
      expect(history().join("\n")).to.match(/working tree/);
    });

    it("refuses to judge without the full history: a shallow clone fails closed", function () {
      put([registration(1, SEPOLIA, "a")], "a");
      put([registration(1, SEPOLIA, "a"), registration(2, BASE_SEPOLIA, "b")], "b");
      const shallow = mkdtempSync(join(tmpdir(), "sp1-registry-shallow-"));
      try {
        execFileSync("git", ["clone", "-q", "--depth", "1", `file://${dir.replace(/\\/g, "/")}`, shallow]);
        expect(fileHistoryErrors(shallow, REGISTRY_REL, registryExtensionErrors).join("\n")).to.match(/full history/);
        expect(directoryHistoryErrors(shallow, "evidence").join("\n")).to.match(/full history/);
      } finally {
        rmSync(shallow, { recursive: true, force: true });
      }
    });

    it("a published directory (designations, builds, bundles) only grows: no file is changed, renamed or removed", function () {
      const d = "evidence/zk/sp1/designations";
      write(`${d}/x-d1.json`, "{}\n");
      commit("d1");
      write(`${d}/x-d2.json`, "{}\n");
      commit("d2");
      expect(directoryHistoryErrors(dir, d)).to.deep.equal([]);
      write(`${d}/x-d1.json`, '{"edited":true}\n');
      const edit = commit("edit d1");
      expect(directoryHistoryErrors(dir, d).join("\n")).to.include(edit.slice(0, 12));
      git("reset", "-q", "--hard", "HEAD~1");
      git("mv", `${d}/x-d2.json`, `${d}/x-d3.json`);
      const rename = commit("rename d2");
      expect(directoryHistoryErrors(dir, d).join("\n")).to.include(rename.slice(0, 12));
      git("reset", "-q", "--hard", "HEAD~1");
      rmSync(join(dir, d, "x-d1.json"));
      expect(directoryHistoryErrors(dir, d).join("\n")).to.match(/working tree/);
    });
  });

  it("this repository's own history keeps the registry, designations, bundles and builds append-only", function () {
    expect(fileHistoryErrors(".", REGISTRY_REL, registryExtensionErrors)).to.deep.equal([]);
    for (const d of [
      "evidence/zk/sp1/designations",
      "evidence/zk/sp1/designation-evidence",
      "evidence/zk/sp1/wrapper-builds",
    ]) {
      expect(directoryHistoryErrors(".", d), d).to.deep.equal([]);
    }
  });
});
