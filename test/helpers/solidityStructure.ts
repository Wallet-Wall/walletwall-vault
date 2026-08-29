import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Minimal lexical source-structure helpers, anchored to function NAMES (survives
 * reformatting/line shifts) rather than line ranges. Deliberately narrow: these
 * prove a function's body text does or doesn't contain a given identifier —
 * nothing about call graphs, external-call classification, or storage-write
 * tracking. Those properties now live in test/helpers/astExternalCallAnalysis.ts
 * and test/helpers/astStorageMutationAnalysis.ts, which read the solc AST
 * instead, because a text/regex search cannot distinguish an internal call from
 * an external one, or follow a storage alias — see
 * docs/Guardian_Authority_Design.md §9.1 L-I and §10.1 item 3.
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

export function readContractSource(repoRelativePath: string): string {
  return readFileSync(join(import.meta.dirname, "..", "..", repoRelativePath), "utf8");
}
