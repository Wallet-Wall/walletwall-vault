import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Minimal source-structure helpers for pinning claims like "this function makes
 * no external call" or "only this function writes X" without a Solidity AST
 * parser dependency. Anchored to function NAMES (survives reformatting/line
 * shifts), not line ranges — see docs/Guardian_Authority_Design.md §9.1 L-I.
 *
 * Deliberately regex-based and narrow in scope: correct for this repo's actual
 * coding style (no multi-line string literals, no nested block comments), not a
 * general-purpose Solidity parser.
 */

/** Removes `//` and `/* *\/` comments while leaving string-literal contents alone. */
export function stripComments(source: string): string {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const two = source.slice(i, i + 2);
    if (two === "//") {
      while (i < source.length && source[i] !== "\n") i++;
      continue;
    }
    if (two === "/*") {
      i += 2;
      while (i < source.length && source.slice(i, i + 2) !== "*/") i++;
      i += 2;
      continue;
    }
    if (source[i] === '"') {
      out += source[i];
      i++;
      while (i < source.length && source[i] !== '"') {
        out += source[i];
        if (source[i] === "\\") {
          i++;
          if (i < source.length) out += source[i];
        }
        i++;
      }
      if (i < source.length) {
        out += source[i];
        i++;
      }
      continue;
    }
    out += source[i];
    i++;
  }
  return out;
}

/**
 * Extracts one function's (or the constructor's) body text, keyed by name. Skips
 * past the parameter list and any modifiers/`returns (...)` clause to find the
 * body's opening brace, then balances braces to find its end. `source` should
 * already be comment-stripped (see {stripComments}) so brace-counting cannot be
 * thrown off by a `{name}` NatSpec cross-reference inside a comment.
 */
export function extractFunctionBody(source: string, functionName: string): string {
  const headerRe =
    functionName === "constructor" ? /constructor\s*\(/ : new RegExp(`\\bfunction\\s+${functionName}\\s*\\(`);
  const headerMatch = headerRe.exec(source);
  if (!headerMatch) {
    throw new Error(`function "${functionName}" not found in source`);
  }

  let i = headerMatch.index + headerMatch[0].length - 1; // at the parameter list's '('
  let depth = 0;
  do {
    if (source[i] === "(") depth++;
    else if (source[i] === ")") depth--;
    i++;
  } while (depth > 0);

  // Skip modifiers / visibility / a `returns (...)` clause up to the body's '{'.
  while (source[i] !== "{") {
    if (source[i] === "(") {
      let pdepth = 1;
      i++;
      while (pdepth > 0) {
        if (source[i] === "(") pdepth++;
        else if (source[i] === ")") pdepth--;
        i++;
      }
      continue;
    }
    i++;
  }
  const bodyStart = i + 1;

  let bdepth = 1;
  let j = bodyStart;
  while (bdepth > 0) {
    if (source[j] === "{") bdepth++;
    else if (source[j] === "}") bdepth--;
    j++;
  }
  return source.slice(bodyStart, j - 1);
}

/** Every top-level `function NAME(` declaration in `source`, in source order (constructor excluded — check it explicitly by name if relevant). */
export function listFunctionNames(source: string): string[] {
  const names: string[] = [];
  const re = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source))) {
    names.push(m[1]);
  }
  return names;
}

export function readContractSource(repoRelativePath: string): string {
  return readFileSync(join(import.meta.dirname, "..", "..", repoRelativePath), "utf8");
}

/**
 * Names of every function (constructor included) whose body mutates the dynamic
 * array mapping `mappingName` — via direct assignment, `delete`, or `.push`/`.pop`.
 * Does not follow storage-pointer aliases (e.g. `Foo storage f = mappingName[k];
 * f.push(...)` would be missed) — sufficient here because none of this repo's
 * mutators of `vaultGuardians` go through an alias; see the test file for why that
 * is the property actually being relied on, not an assumed one.
 */
export function functionsThatMutateArrayMapping(source: string, mappingName: string): string[] {
  const clean = stripComments(source);
  const names = [...listFunctionNames(clean), "constructor"];
  const writePattern = new RegExp(
    `${mappingName}\\s*\\[[^\\]]*\\]\\s*=(?!=)` + // direct assignment, not `==`
      `|delete\\s+${mappingName}\\s*\\[` +
      `|${mappingName}\\s*\\[[^\\]]*\\]\\s*\\.\\s*(push|pop)\\s*\\(`,
  );
  const writers: string[] = [];
  for (const name of names) {
    let body: string;
    try {
      body = extractFunctionBody(clean, name);
    } catch {
      continue; // e.g. no explicit constructor in this file
    }
    if (writePattern.test(body)) writers.push(name);
  }
  return writers;
}
