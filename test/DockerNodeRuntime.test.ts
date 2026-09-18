/**
 * Operations guard for the Node runtime of the shipped Docker image (B3): every stage of the Dockerfile runs one exact
 * Node release, and that release is admitted both by the repository and by the toolchain the image installs.
 *
 * The image builds in two stages. The builder runs `npm ci --include=dev` and `npm run compile` (`hardhat compile`); the
 * runner copies the builder's node_modules and compiled artifacts and serves `npx hardhat node`. Two authorities bound
 * the Node release those stages may run:
 *   - the repository: `engines.node` in package.json;
 *   - the toolchain: the Hardhat CLI exits when Node is below the floor it enforces (MIN_SUPPORTED_NODE_VERSION, checked
 *     by its bin entry point before anything else loads), and Hardhat and EDR, the runtime `hardhat node` executes on,
 *     may declare an `engines.node` of their own. EDR's is not advisory: below it npm silently skips EDR's native binary
 *     (measured: on Node 20.20.2 `npm ci` installs every locked package except @nomicfoundation/edr-linux-x64-gnu).
 * npm only WARNS about an engines mismatch, so an image below the Hardhat floor installs its dependencies cleanly and
 * then fails at `npm run compile`. That is how the image shipped on node:20-slim: Node 20.20.2 passed `npm ci` with two
 * EBADENGINE warnings, then the build stopped at "You are using Node.js 20.20.2 which is not supported by Hardhat.
 * Please upgrade to Node.js 22.13.0 or later." No CI job builds the image, so nothing noticed.
 *
 * The toolchain floor is read from the INSTALLED packages, never copied here, so a dependency bump that raises it fails
 * this guard instead of the next image build; and the installed versions must be the ones package-lock.json pins,
 * because the image installs from the lockfile. A stage must meet EVERY authority: package.json alone admits 22.10.0,
 * which the Hardhat CLI refuses.
 *
 * Every stage must also run the same image: the runner executes the node_modules the builder installed, including EDR's
 * native addon, which npm selects for the builder's platform and C library.
 *
 * A release the repository cannot see is not admitted. A tag without an exact MAJOR.MINOR.PATCH (`node:22-slim`,
 * `node:lts-slim`) is resolved by the registry at build time, so it fails; and a Dockerfile shape the reader does not
 * model (FROM flags, a build argument without a default, heredocs, the escape directive) throws instead of passing.
 *
 * Pure static read in the style of test/ComposeSecretsAndRpcExposure.test.ts: no Docker, no network.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { expect } from "chai";

/** Names under which Docker Hub serves the official Node image. */
const OFFICIAL_NODE_IMAGES = ["node", "library/node", "docker.io/library/node"];

/**
 * Toolchain packages whose declared `engines.node` also bounds the image: Hardhat, whose CLI every build and run command
 * goes through, and EDR, the runtime `hardhat node` executes on.
 */
const TOOLCHAIN_PACKAGES = ["hardhat", "@nomicfoundation/edr"];

/** The module of the installed Hardhat that holds the floor its CLI entry point enforces before loading anything. */
const HARDHAT_FLOOR_MODULE = "dist/src/internal/cli/node-version.js";

// ── Reader ──────────────────────────────────────────────────────────────────────────────────────────────────────────

interface Version {
  major: number;
  minor: number;
  patch: number;
}

/** A floor every stage's Node release must meet, and the authority that sets it. */
interface Floor {
  source: string;
  floor: Version;
}

/** The Node release an image tag names: exact with all three components, a whole line or minor otherwise. */
interface TagRelease {
  major: number;
  minor: number | null;
  patch: number | null;
}

interface Stage {
  /** 1-based line of the FROM instruction. */
  line: number;
  /** The name after AS, lowercased as Docker compares it; null for an unnamed stage. */
  name: string | null;
  /** The base image with global build arguments substituted; an official Node image is normalized to node:<tag>. */
  image: string;
  /** Whether the base is the official Node image, directly or through the earlier stage it builds on. */
  official: boolean;
  /** The release the tag names; null when it names none (lts, latest, a codename, no tag at all). */
  release: TagRelease | null;
  /** Where this stage copies files from (COPY --from, RUN --mount from=), lowercased. */
  copiesFrom: string[];
}

interface Finding {
  /** The stage concerned, or "*" for the Dockerfile as a whole. */
  stage: string;
  kind: "no-stage" | "not-node" | "no-release" | "inexact" | "below-floor" | "split-image" | "outside-copy";
  /** For below-floor: the authority whose floor is missed. */
  source?: string;
  message: string;
}

const show = (version: Version): string => `${version.major}.${version.minor}.${version.patch}`;
const stageName = (stage: Stage): string => stage.name ?? `line ${stage.line}`;
const label = (stage: Stage): string => `stage ${stageName(stage)} (Dockerfile:${stage.line}, ${stage.image})`;

/** Negative, zero or positive as `a` is below, equal to or above `b`, compared as numbers, never as strings. */
function compareVersions(a: Version, b: Version): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

/**
 * The lower bound of an `engines.node` range. Only the shape this repository and its toolchain use is modeled, a single
 * `>=` comparator with one to three numeric components (`>=22.10.0`, `>= 22`); anything else (`^22`, `22.x`,
 * `>=22 <24`, `20 || >=22`, a pre-release) throws, so a range this reader cannot evaluate fails the guard instead of
 * passing it. Missing components are zero, as semver reads them.
 */
function lowerBoundOf(range: string, source: string): Version {
  const match = /^\s*>=\s*(\d+)(?:\.(\d+)(?:\.(\d+))?)?\s*$/.exec(range);
  if (match === null) {
    throw new Error(`${source}: engines.node "${range}" is not a single ">=" bound this guard can evaluate`);
  }
  return { major: Number(match[1]), minor: Number(match[2] ?? 0), patch: Number(match[3] ?? 0) };
}

interface Instruction {
  line: number;
  keyword: string;
  args: string;
}

/**
 * The instructions of a Dockerfile as its frontend reads them: comment lines dropped (a `#` starts a comment only at the
 * start of a line), blank lines skipped, continued lines joined, keywords upper-cased. A leading `escape` parser
 * directive would change how lines continue and a heredoc body would read as instructions, so both throw.
 */
function instructionsOf(text: string): Instruction[] {
  const lines = text.split(/\r?\n/);
  let at = 0;
  // Parser directives are `# key=value` lines at the very top; the first other line ends them.
  for (; at < lines.length; at++) {
    const directive = /^#\s*([A-Za-z]+)\s*=/.exec(lines[at]);
    if (directive === null) break;
    if (directive[1].toLowerCase() === "escape") {
      throw new Error(`Dockerfile:${at + 1}: the escape directive is not modeled`);
    }
  }
  const instructions: Instruction[] = [];
  let pending: { line: number; text: string } | null = null;
  for (; at < lines.length; at++) {
    const raw = lines[at];
    // A comment line is dropped even inside a continued instruction, and a blank line never ends one.
    if (/^\s*#/.test(raw) || raw.trim() === "") continue;
    const continues = /\\\s*$/.test(raw);
    const body = raw.replace(/\\\s*$/, "").trim();
    pending = pending === null ? { line: at + 1, text: body } : { line: pending.line, text: `${pending.text} ${body}` };
    if (continues) continue;
    if (/<<-?\s*["']?[A-Za-z_]/.test(pending.text)) {
      throw new Error(`Dockerfile:${pending.line}: heredocs are not modeled`);
    }
    const [keyword, ...rest] = pending.text.split(/\s+/);
    instructions.push({ line: pending.line, keyword: keyword.toUpperCase(), args: rest.join(" ") });
    pending = null;
  }
  if (pending !== null) throw new Error(`Dockerfile:${pending.line}: the file ends inside a continued instruction`);
  return instructions;
}

/** One declaration of an ARG instruction: NAME, or NAME=literal with an unquoted value and no reference. */
const ARG_DECLARATION = /^([A-Za-z_][A-Za-z0-9_]*)(?:=([A-Za-z0-9._:@/+-]*))?$/;

/** `text` with each `$NAME` and `${NAME}` replaced by the default of a build argument declared before the first FROM. */
function substituteArgs(text: string, globals: Map<string, string | null>, where: string): string {
  if (text.includes("\\$")) throw new Error(`${where}: an escaped $ is not modeled`);
  return text.replace(
    /\$\{([^}]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|\$/g,
    (_match: string, braced: string | undefined, bare: string | undefined) => {
      const name = braced ?? bare;
      if (name === undefined || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new Error(`${where}: only $NAME and \${NAME} build-argument references are modeled`);
      }
      const value = globals.get(name);
      if (value === undefined) throw new Error(`${where}: ${name} is not declared by an ARG before the first FROM`);
      if (value === null) throw new Error(`${where}: ${name} has no default, so the build chooses the image`);
      return value;
    },
  );
}

/** The leading `--flag` words of an instruction's arguments. */
function leadingFlags(args: string): string[] {
  const flags: string[] = [];
  for (const word of args.split(/\s+/)) {
    if (!word.startsWith("--")) break;
    flags.push(word);
  }
  return flags;
}

/** The stage a FROM instruction opens, given its arguments after build-argument substitution. */
function stageOf(args: string, line: number, earlier: Stage[], where: string): Stage {
  const words = args.split(/\s+/);
  if (words[0].startsWith("--")) throw new Error(`${where}: FROM flags (${words[0]}) are not modeled`);
  if (!(words.length === 1 || (words.length === 3 && words[1].toUpperCase() === "AS"))) {
    throw new Error(`${where}: FROM "${args}" is neither "<image>" nor "<image> AS <name>"`);
  }
  const name = words.length === 3 ? words[2].toLowerCase() : null;
  // A stage built on an earlier stage runs that stage's image.
  const parent = earlier.find((stage) => stage.name !== null && stage.name === words[0].toLowerCase());
  if (parent !== undefined) return { ...parent, line, name, copiesFrom: [] };

  const [reference, digest, ...extra] = words[0].split("@");
  if (extra.length > 0 || (digest !== undefined && !/^sha256:[0-9a-f]{64}$/.test(digest))) {
    throw new Error(`${where}: the image reference "${words[0]}" is not modeled`);
  }
  const colon = reference.lastIndexOf(":");
  const tagged = colon > reference.lastIndexOf("/");
  const repository = tagged ? reference.slice(0, colon) : reference;
  const tag = tagged ? reference.slice(colon + 1) : null;
  if (!OFFICIAL_NODE_IMAGES.includes(repository)) {
    return { line, name, image: words[0], official: false, release: null, copiesFrom: [] };
  }
  const parts = tag === null ? null : /^(\d+)(?:\.(\d+)(?:\.(\d+))?)?(?:-[a-z0-9][a-z0-9._-]*)?$/.exec(tag);
  const release =
    parts === null
      ? null
      : {
          major: Number(parts[1]),
          minor: parts[2] === undefined ? null : Number(parts[2]),
          patch: parts[3] === undefined ? null : Number(parts[3]),
        };
  const image = `node${tag === null ? "" : `:${tag}`}${digest === undefined ? "" : `@${digest}`}`;
  return { line, name, image, official: true, release, copiesFrom: [] };
}

/**
 * The stages of a Dockerfile, each base image resolved as Docker resolves it: a FROM line sees only the build arguments
 * declared BEFORE the first FROM (an ARG inside a stage is scoped to that stage), with their defaults.
 */
function readStages(text: string): Stage[] {
  const globals = new Map<string, string | null>();
  const stages: Stage[] = [];
  for (const { line, keyword, args } of instructionsOf(text)) {
    const where = `Dockerfile:${line}`;
    if (keyword === "FROM") {
      stages.push(stageOf(substituteArgs(args, globals, where), line, stages, where));
    } else if (stages.length === 0) {
      if (keyword !== "ARG") throw new Error(`${where}: ${keyword} before the first FROM is not modeled`);
      for (const declaration of args.split(/\s+/)) {
        const match = ARG_DECLARATION.exec(declaration);
        if (match === null) throw new Error(`${where}: ARG "${declaration}" is not NAME or NAME=literal`);
        globals.set(match[1], match[2] ?? null);
      }
    } else if (keyword === "COPY" || keyword === "RUN") {
      for (const flag of leadingFlags(args)) {
        const source =
          keyword === "COPY" ? /^--from=(.+)$/.exec(flag)?.[1] : /^--mount=(?:.*,)?from=([^,]+)/.exec(flag)?.[1];
        if (source !== undefined) stages[stages.length - 1].copiesFrom.push(source.toLowerCase());
      }
    }
  }
  return stages;
}

/** Stages that do not run the official Node image at one exact release. */
function releaseFindings(stages: Stage[]): Finding[] {
  if (stages.length === 0) return [{ stage: "*", kind: "no-stage", message: "the Dockerfile declares no stage" }];
  const findings: Finding[] = [];
  for (const stage of stages) {
    const at = stageName(stage);
    if (!stage.official) {
      findings.push({ stage: at, kind: "not-node", message: `${label(stage)} is not the official Node image` });
    } else if (stage.release === null) {
      findings.push({
        stage: at,
        kind: "no-release",
        message: `${label(stage)} names no Node release, so the registry picks one at build time`,
      });
    } else if (stage.release.minor === null || stage.release.patch === null) {
      findings.push({
        stage: at,
        kind: "inexact",
        message: `${label(stage)} names no exact MAJOR.MINOR.PATCH release, so the registry picks it at build time`,
      });
    }
  }
  return findings;
}

/** Stages whose tag can resolve to a release below a floor: an inexact tag is judged by the lowest release it names. */
function floorFindings(stages: Stage[], floors: Floor[]): Finding[] {
  const findings: Finding[] = [];
  for (const stage of stages) {
    if (stage.release === null) continue;
    const { major, minor, patch } = stage.release;
    const lowest = { major, minor: minor ?? 0, patch: patch ?? 0 };
    const named = minor === null ? `${major}.x` : patch === null ? `${major}.${minor}.x` : show(lowest);
    for (const { source, floor } of floors) {
      if (compareVersions(lowest, floor) >= 0) continue;
      findings.push({
        stage: stageName(stage),
        kind: "below-floor",
        source,
        message: `${label(stage)} runs Node ${named} (as low as ${show(lowest)}), below ${show(floor)} required by ${source}`,
      });
    }
  }
  return findings;
}

/** A split between stages: more than one image, or files copied in from outside the build. */
function consistencyFindings(stages: Stage[]): Finding[] {
  const findings: Finding[] = [];
  if (new Set(stages.map((stage) => stage.image)).size > 1) {
    findings.push({
      stage: "*",
      kind: "split-image",
      message:
        `stages run different images (${stages.map((stage) => `${stageName(stage)}: ${stage.image}`).join(", ")}); ` +
        "the runner executes the node_modules the builder installed, so every stage must run the same Node image",
    });
  }
  stages.forEach((stage, index) => {
    for (const source of stage.copiesFrom) {
      const earlier = stages.slice(0, index);
      if (earlier.some((other, at) => other.name === source || String(at) === source)) continue;
      findings.push({
        stage: stageName(stage),
        kind: "outside-copy",
        message: `${label(stage)} copies files from ${source}, which is not an earlier stage of this build`,
      });
    }
  });
  return findings;
}

/** Everything wrong with a Dockerfile's Node runtime against the given floors; [] when it is sound. */
function runtimeFindings(text: string, floors: Floor[]): Finding[] {
  const stages = readStages(text);
  return [...releaseFindings(stages), ...floorFindings(stages, floors), ...consistencyFindings(stages)];
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

/**
 * The floor of each authority: package.json, every declared toolchain `engines.node`, and the floor the installed Hardhat
 * CLI enforces. Each toolchain package must be the version package-lock.json pins, since the image installs from the
 * lockfile and the floor read here must be the one its build enforces.
 */
async function repositoryFloors(): Promise<Floor[]> {
  const manifest = readJson("package.json") as { engines?: { node?: unknown } };
  const engine = manifest.engines?.node;
  if (typeof engine !== "string") throw new Error("package.json declares no engines.node");
  const floors: Floor[] = [
    { source: `package.json engines.node "${engine}"`, floor: lowerBoundOf(engine, "package.json") },
  ];

  const lock = readJson("package-lock.json") as { packages?: Record<string, { version?: unknown }> };
  const installed = new Map<string, string>();
  for (const name of TOOLCHAIN_PACKAGES) {
    const pkg = readJson(`node_modules/${name}/package.json`) as { version?: unknown; engines?: { node?: unknown } };
    const locked = lock.packages?.[`node_modules/${name}`]?.version;
    if (typeof pkg.version !== "string" || pkg.version !== locked) {
      throw new Error(`${name}: node_modules holds ${String(pkg.version)}, package-lock.json pins ${String(locked)}`);
    }
    installed.set(name, pkg.version);
    const declared = pkg.engines?.node;
    if (declared === undefined) continue;
    if (typeof declared !== "string") throw new Error(`${name}@${pkg.version}: engines.node is not a string`);
    const source = `${name}@${pkg.version} engines.node "${declared}"`;
    floors.push({ source, floor: lowerBoundOf(declared, `${name}@${pkg.version}`) });
  }

  const hardhat = `hardhat@${installed.get("hardhat")}`;
  const floorModule = pathToFileURL(resolve("node_modules/hardhat", HARDHAT_FLOOR_MODULE)).href;
  const enforced = ((await import(floorModule)) as Record<string, unknown>).MIN_SUPPORTED_NODE_VERSION;
  if (!Array.isArray(enforced) || enforced.length !== 3 || !enforced.every((n) => Number.isInteger(n) && n >= 0)) {
    throw new Error(
      `${hardhat}: ${HARDHAT_FLOOR_MODULE} no longer exports MIN_SUPPORTED_NODE_VERSION as [major, minor, patch]; ` +
        "re-derive where the Hardhat CLI enforces its Node floor before trusting this guard",
    );
  }
  const [major, minor, patch] = enforced as number[];
  floors.push({ source: `the ${hardhat} CLI (MIN_SUPPORTED_NODE_VERSION)`, floor: { major, minor, patch } });
  return floors;
}

const messages = (findings: Finding[]): string[] => findings.map((finding) => finding.message);

describe("Docker runtime guard — every stage runs one Node release the repository and its toolchain admit (B3)", function () {
  const dockerfile = readFileSync(resolve("Dockerfile"), "utf8");
  let stages: Stage[] = [];
  let floors: Floor[] = [];

  before(async function () {
    stages = readStages(dockerfile);
    floors = await repositoryFloors();
  });

  const isRepository = (floor: Floor): boolean => floor.source.startsWith("package.json");

  it("reads a floor from each authority: package.json and the CLI of the installed, lock-pinned Hardhat", function () {
    const sources = floors.map((floor) => floor.source);
    expect(
      sources.filter((source) => source.startsWith("package.json ")),
      sources.join("; "),
    ).to.have.length(1);
    expect(
      sources.filter((source) => /^the hardhat@\S+ CLI /.test(source)),
      sources.join("; "),
    ).to.have.length(1);
  });

  it("reads every FROM of the shipped Dockerfile as a stage, so none escapes the checks below", function () {
    // An independent count: physical lines that open a FROM instruction.
    const fromLines = dockerfile.split(/\r?\n/).filter((line) => /^\s*FROM\s/i.test(line)).length;
    expect(fromLines, "FROM lines in the Dockerfile").to.be.greaterThan(0);
    expect(stages.map(label), "stages the reader returned").to.have.length(fromLines);
  });

  it("runs the official Node image at one exact release in every stage", function () {
    expect(messages(releaseFindings(stages))).to.deep.equal([]);
  });

  it("meets the Node floor of the repository's engines.node in every stage", function () {
    expect(messages(floorFindings(stages, floors.filter(isRepository)))).to.deep.equal([]);
  });

  it("meets every toolchain floor — the installed Hardhat CLI's, and each declared engines.node — in every stage", function () {
    expect(
      messages(
        floorFindings(
          stages,
          floors.filter((floor) => !isRepository(floor)),
        ),
      ),
    ).to.deep.equal([]);
  });

  it("runs the same Node image in every stage, and copies files only from earlier stages", function () {
    expect(messages(consistencyFindings(stages))).to.deep.equal([]);
  });

  describe("reader self-check on synthetic Dockerfiles (a parsing regression must not pass silently)", function () {
    const FLOORS: Floor[] = [
      { source: "package.json", floor: { major: 22, minor: 10, patch: 0 } },
      { source: "the Hardhat CLI", floor: { major: 22, minor: 13, patch: 0 } },
    ];
    const ADMITTED = "node:22.23.2-bookworm-slim";
    const NODE_20 = "node:20.20.2-bookworm-slim";

    /** A two-stage Dockerfile shaped like the shipped one, on the given base images. */
    const twoStage = (builder: string, runner: string, extra: string[] = []): string =>
      [
        `FROM ${builder} AS builder`,
        "WORKDIR /app",
        "RUN apt-get update && apt-get install -y --no-install-recommends \\",
        "    python3 \\",
        "    && rm -rf /var/lib/apt/lists/*",
        "COPY package*.json ./",
        "RUN npm ci --include=dev",
        "COPY . .",
        "RUN npm run compile",
        "",
        `FROM ${runner} AS runner`,
        "COPY --from=builder /app/node_modules ./node_modules",
        'CMD ["npx", "hardhat", "node", "--hostname", "0.0.0.0"]',
        ...extra,
      ].join("\n");

    /** Findings as compact `stage:kind[:source]` strings. */
    const verdict = (text: string, floors: Floor[] = FLOORS): string[] =>
      runtimeFindings(text, floors).map((f) =>
        [f.stage, f.kind, ...(f.source === undefined ? [] : [f.source])].join(":"),
      );

    it("compares releases as numbers, component by component", function () {
      const at = (text: string): Version => {
        const [major, minor, patch] = text.split(".").map(Number);
        return { major, minor, patch };
      };
      expect(compareVersions(at("22.12.9"), at("22.13.0"))).to.be.lessThan(0);
      expect(compareVersions(at("22.13.0"), at("22.13.0"))).to.equal(0);
      expect(
        compareVersions(at("22.13.10"), at("22.13.9")),
        "10 > 9, where strings compare otherwise",
      ).to.be.greaterThan(0);
      expect(compareVersions(at("23.0.0"), at("22.99.99"))).to.be.greaterThan(0);
    });

    it("reads a single >= engines bound and refuses every other range shape", function () {
      expect(lowerBoundOf(">=22.10.0", "t")).to.deep.equal({ major: 22, minor: 10, patch: 0 });
      expect(lowerBoundOf(">= 22", "t")).to.deep.equal({ major: 22, minor: 0, patch: 0 });
      expect(lowerBoundOf(">=22.13", "t")).to.deep.equal({ major: 22, minor: 13, patch: 0 });
      for (const range of [
        "^22.10.0",
        "~22.10",
        "22.x",
        "22",
        ">=22 <24",
        "20 || >=22",
        ">22.10.0",
        ">=22.10.0-rc.1",
        "*",
        "",
      ]) {
        expect(() => lowerBoundOf(range, "t"), range).to.throw(/not a single ">=" bound/);
      }
    });

    it("passes one exact admitted release in both stages, and fails Node 20 in the builder, the runner, or both", function () {
      expect(verdict(twoStage(ADMITTED, ADMITTED))).to.deep.equal([]);
      expect(verdict(twoStage(NODE_20, NODE_20))).to.deep.equal([
        "builder:below-floor:package.json",
        "builder:below-floor:the Hardhat CLI",
        "runner:below-floor:package.json",
        "runner:below-floor:the Hardhat CLI",
      ]);
      // Builder upgraded, runner left behind: the runner still runs Node 20, and the stages split.
      expect(verdict(twoStage(ADMITTED, NODE_20))).to.deep.equal([
        "runner:below-floor:package.json",
        "runner:below-floor:the Hardhat CLI",
        "*:split-image",
      ]);
      // Runner upgraded, builder left behind: the build itself still runs on Node 20.
      expect(verdict(twoStage(NODE_20, ADMITTED))).to.deep.equal([
        "builder:below-floor:package.json",
        "builder:below-floor:the Hardhat CLI",
        "*:split-image",
      ]);
    });

    it("fails a split between stages even when each release is admitted on its own", function () {
      expect(verdict(twoStage(ADMITTED, "node:22.22.0-bookworm-slim"))).to.deep.equal(["*:split-image"]);
      expect(verdict(twoStage("node:22.23.2-slim", ADMITTED)), "same release, different variant").to.deep.equal([
        "*:split-image",
      ]);
      expect(verdict(twoStage(ADMITTED, "debian:bookworm-slim"))).to.deep.equal(["runner:not-node", "*:split-image"]);
    });

    it("fails a tag that leaves the release to the registry, judging a floating tag by its lowest release", function () {
      // The shape the image shipped with: every Node 20 release is below both floors.
      expect(verdict(twoStage("node:20-slim", "node:20-slim"))).to.deep.equal([
        "builder:inexact",
        "runner:inexact",
        "builder:below-floor:package.json",
        "builder:below-floor:the Hardhat CLI",
        "runner:below-floor:package.json",
        "runner:below-floor:the Hardhat CLI",
      ]);
      // A floating 22 tag could resolve below the floor; a floating 24 tag cannot, but is still not exact.
      expect(verdict(twoStage("node:22-slim", "node:22-slim"))).to.have.members([
        "builder:inexact",
        "runner:inexact",
        "builder:below-floor:package.json",
        "builder:below-floor:the Hardhat CLI",
        "runner:below-floor:package.json",
        "runner:below-floor:the Hardhat CLI",
      ]);
      expect(verdict(twoStage("node:24-slim", "node:24-slim"))).to.deep.equal(["builder:inexact", "runner:inexact"]);
      expect(verdict(twoStage("node:lts-slim", "node:lts-slim"))).to.deep.equal([
        "builder:no-release",
        "runner:no-release",
      ]);
      expect(verdict(twoStage("node", "node"))).to.deep.equal(["builder:no-release", "runner:no-release"]);
    });

    it("judges each stage against every floor: a lowered engines field cannot admit Node 20, a raised one rejects 22", function () {
      const repository = (major: number): Floor[] => [
        { source: "package.json", floor: { major, minor: 0, patch: 0 } },
        FLOORS[1],
      ];
      expect(verdict(twoStage(NODE_20, NODE_20), repository(20))).to.deep.equal([
        "builder:below-floor:the Hardhat CLI",
        "runner:below-floor:the Hardhat CLI",
      ]);
      expect(verdict(twoStage(ADMITTED, ADMITTED), repository(24))).to.deep.equal([
        "builder:below-floor:package.json",
        "runner:below-floor:package.json",
      ]);
    });

    it("reads every stage, not just the first and last", function () {
      expect(verdict(twoStage(ADMITTED, ADMITTED, [`FROM ${NODE_20} AS test`]))).to.deep.equal([
        "test:below-floor:package.json",
        "test:below-floor:the Hardhat CLI",
        "*:split-image",
      ]);
      // A stage built on an earlier stage runs that stage's image.
      expect(verdict(twoStage(ADMITTED, ADMITTED, ["FROM builder AS test"]))).to.deep.equal([]);
      expect(verdict("")).to.deep.equal(["*:no-stage"]);
    });

    it("substitutes global build arguments into FROM in both spellings, and never a stage-scoped one", function () {
      const text = [
        "ARG NODE_VERSION=22.23.2",
        "FROM node:${NODE_VERSION}-bookworm-slim AS builder",
        // Declared inside the builder stage, so it is invisible to the next FROM.
        "ARG NODE_VERSION=20.20.2",
        "FROM node:$NODE_VERSION-bookworm-slim AS runner",
        "COPY --from=builder /app/node_modules ./node_modules",
      ].join("\n");
      expect(readStages(text).map((stage) => stage.image)).to.deep.equal([ADMITTED, ADMITTED]);
      expect(verdict(text)).to.deep.equal([]);
      expect(verdict(text.replace("ARG NODE_VERSION=22.23.2", "ARG NODE_VERSION=20.20.2"))).to.deep.equal([
        "builder:below-floor:package.json",
        "builder:below-floor:the Hardhat CLI",
        "runner:below-floor:package.json",
        "runner:below-floor:the Hardhat CLI",
      ]);
    });

    it("ignores comments, including a commented-out FROM, and joins an instruction continued across lines", function () {
      const commented = [
        "# syntax=docker/dockerfile:1",
        "# FROM node:20-slim AS builder",
        twoStage(ADMITTED, ADMITTED).replace(
          "FROM node:22.23.2-bookworm-slim AS runner",
          "FROM \\\n  # node:20-slim\n  node:22.23.2-bookworm-slim AS runner",
        ),
      ].join("\n");
      expect(readStages(commented).map(stageName)).to.deep.equal(["builder", "runner"]);
      expect(verdict(commented)).to.deep.equal([]);
    });

    it("normalizes the official image's spellings and accepts a digest pin beside the exact tag", function () {
      expect(verdict(twoStage(`docker.io/library/${ADMITTED}`, `library/${ADMITTED}`))).to.deep.equal([]);
      const pinned = `${ADMITTED}@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5`;
      expect(verdict(twoStage(pinned, pinned))).to.deep.equal([]);
      expect(verdict(twoStage(`someone/${ADMITTED}`, `someone/${ADMITTED}`))).to.deep.equal([
        "builder:not-node",
        "runner:not-node",
      ]);
    });

    it("fails files copied into a stage from outside the build", function () {
      const smuggled = "COPY --from=node:20-slim /usr/local/bin/node /usr/local/bin/node";
      expect(verdict(twoStage(ADMITTED, ADMITTED, [smuggled]))).to.deep.equal(["runner:outside-copy"]);
      const mounted = "RUN --mount=type=bind,from=node:20-slim,source=/usr/local/bin,target=/opt/node node --version";
      expect(verdict(twoStage(ADMITTED, ADMITTED, [mounted]))).to.deep.equal(["runner:outside-copy"]);
    });

    it("fails closed on Dockerfile shapes the reader does not model", function () {
      const unmodeled: Record<string, string> = {
        "a FROM flag": `FROM --platform=linux/amd64 ${ADMITTED} AS builder`,
        "a build argument without a default": "ARG NODE_VERSION\nFROM node:${NODE_VERSION}-bookworm-slim",
        "an undeclared build argument": "FROM node:${NODE_VERSION}-bookworm-slim",
        "a substitution modifier": "ARG NODE_VERSION=22.23.2\nFROM node:${NODE_VERSION:-20.20.2}-bookworm-slim",
        "a quoted build-argument value": 'ARG NODE_VERSION="22.23.2"\nFROM node:${NODE_VERSION}-bookworm-slim',
        "the escape directive": `# escape=\`\nFROM ${ADMITTED}`,
        "a heredoc": `FROM ${ADMITTED}\nRUN <<EOF\nFROM node:20-slim\nEOF`,
        "a continuation at the end of the file": `FROM ${ADMITTED} \\`,
        "words after the stage name": `FROM ${ADMITTED} AS runner # not a comment mid-line`,
        "an instruction other than ARG before the first FROM": `RUN true\nFROM ${ADMITTED}`,
      };
      for (const [shape, text] of Object.entries(unmodeled)) expect(() => readStages(text), shape).to.throw();
    });
  });
});
