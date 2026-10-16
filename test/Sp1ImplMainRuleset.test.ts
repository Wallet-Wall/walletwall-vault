/**
 * SP1 implementation lane: main's history protection, measured (scripts/lib/main-ruleset.ts,
 * scripts/measure-main-ruleset.ts; review finding AUTH-3).
 *
 * The append-only proof walks the history it is given, so it cannot see a rewrite of main itself. What forbids one is
 * main's ruleset, which lives in GitHub: it is recorded by a read-only GET and the receipt states what it shows. These
 * tests read the committed observation and perturb copies of it: every gap that would let main's history be rewritten
 * is named, and a malformed observation is no observation.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import {
  MAIN_RULESET_ID,
  MAIN_RULESET_OBSERVATION_REL,
  MAIN_RULESET_REQUEST,
  historyProtectionGaps,
  rulesetObservationErrors,
  type RulesetObservation,
} from "../scripts/lib/main-ruleset";

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

describe("SP1 implementation lane — main's history protection, measured", function () {
  let committed: RulesetObservation;

  before(function () {
    committed = JSON.parse(readFileSync(resolve(MAIN_RULESET_OBSERVATION_REL), "utf8"));
  });

  it("the committed observation is ruleset 21256062 as GitHub reported it: main can be neither force-pushed nor deleted, and nobody bypasses that", function () {
    expect(rulesetObservationErrors(committed)).to.deep.equal([]);
    expect(historyProtectionGaps(committed)).to.deep.equal([]);
    expect(committed.request).to.equal(MAIN_RULESET_REQUEST);
    expect(committed.response.id).to.equal(MAIN_RULESET_ID);
    expect(committed.response.rules.map((r) => r.type)).to.include.members(["non_fast_forward", "deletion"]);
    expect(committed.response.bypass_actors).to.deep.equal([]);
  });

  const gaps: [string, (o: RulesetObservation) => void, RegExp][] = [
    [
      "no non_fast_forward rule (force pushes allowed)",
      (o) => (o.response.rules = o.response.rules.filter((r) => r.type !== "non_fast_forward")),
      /force push/,
    ],
    ["no deletion rule", (o) => (o.response.rules = o.response.rules.filter((r) => r.type !== "deletion")), /deleted/],
    [
      "an actor who can bypass it",
      (o) => o.response.bypass_actors.push({ actor_id: 5, actor_type: "RepositoryRole" }),
      /bypass/,
    ],
    ["a measuring account that can bypass it", (o) => (o.response.current_user_can_bypass = "always"), /bypass/],
    ["enforcement only evaluated", (o) => (o.response.enforcement = "evaluate"), /not active/],
    ["enforcement disabled", (o) => (o.response.enforcement = "disabled"), /not active/],
    ["another target", (o) => (o.response.target = "tag"), /branch/],
    ["main not covered", (o) => (o.response.conditions.ref_name.include = ["refs/heads/release"]), /does not cover/],
    ["main excluded", (o) => o.response.conditions.ref_name.exclude.push("refs/heads/main"), /excludes/],
  ];
  for (const [label, change, rule] of gaps) {
    it(`names the gap: ${label}`, function () {
      const o = clone(committed);
      change(o);
      expect(rulesetObservationErrors(o), "still a well-formed observation").to.deep.equal([]);
      expect(historyProtectionGaps(o).join("\n")).to.match(rule);
    });
  }

  it("the default branch, or every branch, covers main", function () {
    for (const include of [["~DEFAULT_BRANCH"], ["~ALL"]]) {
      const o = clone(committed);
      o.response.conditions.ref_name.include = include;
      expect(historyProtectionGaps(o), include[0]).to.deep.equal([]);
    }
  });

  it("a malformed or foreign observation is no observation", function () {
    const cases: [string, (o: RulesetObservation) => void, RegExp][] = [
      ["another schema", (o) => (o.schema = "x"), /schema/],
      ["another request", (o) => (o.request = "GET /repos/elsewhere/rulesets/1"), /request/],
      ["another ruleset", (o) => (o.response.id = 1), /ruleset 21256062/],
      ["no time", (o) => (o.observedAtUtc = ""), /observedAtUtc/],
      ["no rules", (o) => delete (o.response as { rules?: unknown }).rules, /rules/],
    ];
    for (const [label, change, rule] of cases) {
      const o = clone(committed);
      change(o);
      expect(rulesetObservationErrors(o).join("\n"), label).to.match(rule);
    }
    expect(rulesetObservationErrors(null as unknown as RulesetObservation).join("\n")).to.match(/schema/);
  });

  it("the measurement is a read-only GET, made by the script that names it", function () {
    const script = readFileSync(resolve("scripts/measure-main-ruleset.ts"), "utf8");
    expect(script).to.match(/execFileSync\(\s*"gh",\s*\["api", "-X", "GET"/);
    expect(script).to.not.match(/"-X", "(POST|PUT|PATCH|DELETE)"|--method/);
    expect(committed.tool).to.match(/scripts\/measure-main-ruleset\.ts/);
  });
});
