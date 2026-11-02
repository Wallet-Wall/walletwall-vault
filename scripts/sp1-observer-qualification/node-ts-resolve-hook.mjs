// SP1-PA3C-Q1: the one resolution Node's own TypeScript type stripping lacks for this repository's observer path.
// The attribution library imports the observer as "../sp1-egress-observer" (no extension, as tsx resolves it); Node
// resolves a relative specifier only to a file that is there, so this hook names the ".ts" file when, and only when, it
// exists. Nothing else is touched: bare names, built-ins and specifiers with an extension pass through unchanged, so
// no node_modules is ever consulted (the clean container holds none). Node built-ins only. Research prototype.
import { statSync } from "node:fs";

/**
 * The ".ts" file a relative, extensionless specifier names, as a file URL, or null when the specifier is not of that
 * kind or the file is not there (`isFile` answers for a file URL).
 */
export function tsCandidate(specifier, parentURL, isFile) {
  if (typeof parentURL !== "string" || !parentURL.startsWith("file:")) return null;
  if (!(specifier.startsWith("./") || specifier.startsWith("../"))) return null;
  if (/\.[A-Za-z0-9]+$/.test(specifier)) return null;
  const candidate = new URL(`${specifier}.ts`, parentURL);
  return isFile(candidate.href) ? candidate.href : null;
}

const isFile = (fileUrl) => {
  try {
    return statSync(new URL(fileUrl)).isFile();
  } catch {
    return false;
  }
};

export async function resolve(specifier, context, next) {
  const candidate = tsCandidate(specifier, context.parentURL, isFile);
  return next(candidate ?? specifier, context);
}
