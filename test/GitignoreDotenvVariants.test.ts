/**
 * Repository-hygiene guard: a populated dotenv file cannot be committed to this PUBLIC repository by accident.
 *
 * A .gitignore pattern matches one literal name unless it wildcards, so a bare `.env` leaves every sibling
 * (`.env.local`, `.env.production`, `.env.test`, any `.env.<suffix>`, `.envrc`) untracked-but-stageable: `git add -A`
 * stages them, and a secret reaches a public history. Unlike a .dockerignore pattern, a slash-free .gitignore pattern
 * matches at ANY depth, so one wildcard rule covers subdirectories too — the two files do not share matching semantics
 * and this guard therefore asserts git's own decision rather than mirroring the Docker rule.
 *
 * `.env.example` is the one dotenv file the repository ships on purpose: a public template the documentation tells
 * operators to copy (`cp .env.example .env`). It must stay outside the ignore rules and inside the index, and that is
 * the positive control proving the rule is a dotenv-secret sweep rather than a blanket dot-file sweep.
 *
 * The decision comes from `git check-ignore -v --no-index`, which reports the rule that decides a path, so this guard
 * tests effective ignore semantics instead of the presence of a line. `--no-index` is what makes the rule itself
 * visible: without it git reports a TRACKED path as "not ignored" whatever the rules say, which would make the
 * positive control vacuous. The deciding source must be the repository's own `.gitignore`, so a developer's global
 * excludes file cannot make this pass on one machine and fail in CI.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

import { expect } from "chai";

/** Dotenv file names that hold secrets as soon as an operator populates them. None may be committable. */
const SECRET_DOTENV_FILES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.production.local",
  ".env.development",
  ".env.development.local",
  ".env.test",
  ".env.sepolia",
  ".env.droplet",
  ".env.2026",
  ".env.a",
  ".envrc",
];

/** The same secrets one directory down, and deeper: a slash-free .gitignore pattern must reach them. */
const NESTED_SECRET_DOTENV_FILES = [
  "scripts/.env",
  "scripts/.env.local",
  "src/.env.production",
  "pqc/.envrc",
  "zkvm/host/.env.local",
  "a/b/c/.env.staging",
];

/** The one dotenv file the repository ships on purpose. */
const PUBLIC_DOTENV_TEMPLATE = ".env.example";

/** The file that must carry the decision: not a global excludes file, not $GIT_DIR/info/exclude. */
const EXPECTED_IGNORE_SOURCE = ".gitignore";

// ── Reader ──────────────────────────────────────────────────────────────────────────────────────────────────────────

interface Decision {
  ignored: boolean;
  /** The file that decided, e.g. ".gitignore"; null when nothing matched. */
  source: string | null;
  /** The deciding pattern, e.g. ".env*"; null when nothing matched. */
  pattern: string | null;
}

/**
 * Git's own ignore decision for `path`.
 *
 * `git check-ignore` exits 1 only when NO pattern matched at all. It exits 0 whenever some pattern matched — and that
 * includes a NEGATED pattern, which means the opposite of ignored. Measured here: `.env.example` returns exit 0 with
 * `.gitignore:12:!.env.example`, while `.env.local` returns exit 0 with `.gitignore:11:.env*`. Reading the exit code
 * as the verdict would therefore call the re-included template "ignored" and make the positive control unfixable. The
 * verdict lives in the reported pattern: a leading `!` re-includes.
 *
 * Exit 1 is a normal answer, not a failure, which is why this uses spawnSync rather than the execFileSync used
 * elsewhere in the suite: execFileSync would throw on it. Any other exit is a real failure and is raised, so a missing
 * git or a broken work tree fails this guard loudly instead of letting it pass by default.
 */
function ignoreDecision(path: string): Decision {
  const run = spawnSync("git", ["check-ignore", "-v", "--no-index", "--", path], {
    cwd: resolve("."),
    encoding: "utf8",
  });
  if (run.error) throw new Error(`git check-ignore could not run for ${path}: ${run.error.message}`);
  if (run.status === 1) return { ignored: false, source: null, pattern: null };
  if (run.status !== 0) {
    throw new Error(`git check-ignore failed for ${path} (exit ${run.status}): ${String(run.stderr).trim()}`);
  }
  // Output is "<source>:<line>:<pattern>\t<pathname>"; the pattern itself may contain ":" so only the first two
  // separators are structural.
  const [described] = String(run.stdout).split("\t");
  const [source, , ...rest] = described.split(":");
  const pattern = rest.join(":");
  return { ignored: !pattern.startsWith("!"), source, pattern };
}

/** Whether `path` is in the index, which is what "shipped on purpose" means for a template. */
function isTracked(path: string): boolean {
  const run = spawnSync("git", ["ls-files", "--error-unmatch", "--", path], { cwd: resolve("."), encoding: "utf8" });
  if (run.error) throw new Error(`git ls-files could not run for ${path}: ${run.error.message}`);
  return run.status === 0;
}

describe("Repository hygiene — a populated dotenv file cannot be committed by accident", function () {
  it("reads git's own decision, telling an ignored path from one no pattern mentions", function () {
    // Reader self-check: without this, a reader that answered "ignored" to everything would satisfy every assertion
    // below, and one that answered "not ignored" to everything would satisfy the positive control.
    const ignored = ignoreDecision("node_modules/some-package/index.js");
    expect(ignored.ignored, "node_modules is ignored by this repository").to.equal(true);
    expect(ignored.source).to.equal(EXPECTED_IGNORE_SOURCE);

    // Shape 2: no pattern matched at all (git exits 1).
    const unmatched = ignoreDecision("README.md");
    expect(unmatched.ignored, "README.md is not ignored").to.equal(false);
    expect(unmatched.pattern, "no pattern should have matched README.md").to.equal(null);

    expect(isTracked("README.md"), "README.md is tracked").to.equal(true);
    expect(isTracked("no/such/file.txt"), "a path that does not exist is not tracked").to.equal(false);
  });

  it("ignores every secret-bearing dotenv variant at the repository root", function () {
    const committable = SECRET_DOTENV_FILES.filter((name) => !ignoreDecision(name).ignored);
    expect(committable, "these dotenv files could be staged by `git add -A`").to.deep.equal([]);
  });

  it("ignores a secret-bearing dotenv variant in a subdirectory, at any depth", function () {
    const committable = NESTED_SECRET_DOTENV_FILES.filter((name) => !ignoreDecision(name).ignored);
    expect(committable, "these nested dotenv files could be staged by `git add -A`").to.deep.equal([]);
  });

  it("ignores an arbitrary .env suffix, so the rule generalizes instead of listing the names known today", function () {
    // A drawn suffix, not a listed one: a rule that enumerates the names known today cannot satisfy this.
    const suffix = Math.random().toString(36).slice(2, 10);
    for (const name of [`.env.${suffix}`, `scripts/.env.${suffix}`, `a/b/c/.env.${suffix}`]) {
      expect(ignoreDecision(name).ignored, `${name} could be staged by \`git add -A\``).to.equal(true);
    }
  });

  it("decides in the repository's own .gitignore, not in a developer's global excludes", function () {
    // Every rule this guard relies on must live in the repository, or it would pass on one machine and fail in CI.
    const elsewhere = SECRET_DOTENV_FILES.concat(NESTED_SECRET_DOTENV_FILES)
      .map((name) => ({ name, decision: ignoreDecision(name) }))
      .filter(({ decision }) => decision.source !== EXPECTED_IGNORE_SOURCE)
      .map(({ name, decision }) => `${name}: ${decision.source ?? "(nothing matched)"}`);
    expect(elsewhere).to.deep.equal([]);
  });

  it(`keeps ${PUBLIC_DOTENV_TEMPLATE} outside the ignore rules and inside the index`, function () {
    // Positive control: the sweep must not become a blanket dot-file rule that also hides the template the repository
    // ships and every runbook tells operators to copy.
    const decision = ignoreDecision(PUBLIC_DOTENV_TEMPLATE);
    expect(
      decision.ignored,
      `${PUBLIC_DOTENV_TEMPLATE} is excluded by ${decision.source}:${decision.pattern}`,
    ).to.equal(false);
    expect(isTracked(PUBLIC_DOTENV_TEMPLATE), `${PUBLIC_DOTENV_TEMPLATE} is not tracked`).to.equal(true);
    // Any sweep general enough to catch an arbitrary suffix also catches the template, so when a pattern does decide
    // this path it must be a deliberate re-inclusion — placed AFTER the sweep, since the last match wins. Asserted by
    // shape rather than exact spelling: `!.env.example` and `!/.env.example` are both valid.
    if (decision.pattern !== null) {
      expect(decision.pattern, "a pattern decides the template, so it must be a re-inclusion").to.match(
        /^!.*\.env\.example$/,
      );
    }
  });

  it("leaves every tracked file committable: no rule hides something the repository already ships", function () {
    // A re-inclusion that is misplaced (before the sweep) or missing would show up here as a tracked file the rules
    // now exclude, which is how a template silently disappears from a fresh contributor's `git add`.
    const listed = spawnSync("git", ["ls-files", "-z"], { cwd: resolve("."), encoding: "utf8" });
    expect(listed.status, "git ls-files failed").to.equal(0);
    const tracked = String(listed.stdout).split("\0").filter(Boolean);
    expect(tracked.length, "no tracked files were listed").to.be.greaterThan(100);
    const hidden = tracked
      .filter((path) => /(^|\/)\.env/.test(path))
      .filter((path) => ignoreDecision(path).ignored)
      .sort();
    expect(hidden, "these tracked dotenv files are excluded by the ignore rules").to.deep.equal([]);
  });
});
