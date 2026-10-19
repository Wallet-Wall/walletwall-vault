// Field-by-field comparison of the TypeScript census and the Python tarfile listing of one archive copy.
// Usage: node compare.mjs <census.json> <tarfile.json>
import { readFileSync } from "node:fs";

const census = JSON.parse(readFileSync(process.argv[2], "utf8"));
const py = JSON.parse(readFileSync(process.argv[3], "utf8"));
const norm = (p) => {
  let s = p.startsWith("./") ? p.slice(2) : p;
  s = s.replace(/\/+$/, "");
  return s === "" || s === "." ? "." : s;
};
const real = census.entries.filter((e) => e.typeflag !== "x" && e.typeflag !== "g");
const problems = [];
if (census.archive.sha256 !== py.archiveSha256) problems.push("archive sha256 differs");
if (real.length !== py.members.length) problems.push(`entry count ${real.length} vs ${py.members.length}`);
real.forEach((e, i) => {
  const m = py.members[i];
  if (!m) return;
  // Python applies a PAX mtime record; the census reports the header's octal field, so compare the integer part.
  const paxMtime = e.pax.some((p) => p.key === "mtime");
  const fields = [
    ["path", norm(e.path), norm(m.name)],
    ["typeflag", e.typeflag, m.typeflag],
    ["size", e.size, m.size],
    ["mode", e.mode, m.mode],
    ["uid", e.uid, m.uid],
    ["gid", e.gid, m.gid],
    ["uname", e.uname, m.uname],
    ["gname", e.gname, m.gname],
    ["mtime", e.mtime, paxMtime ? e.mtime : m.mtime],
    ["linkname", e.linkname, m.linkname],
    ["sha256", e.dataSha256, m.dataSha256],
    ["paxKeys", e.pax.map((p) => p.key).sort().join(","), m.paxKeys.join(",")],
  ];
  for (const [k, a, b] of fields) if (a !== b) problems.push(`entry ${i} ${k}: ${a} vs ${b}`);
  if (paxMtime && Math.abs(m.mtime - e.mtime) > 1) problems.push(`entry ${i} PAX mtime ${m.mtime} vs header ${e.mtime}`);
});
console.log(problems.length === 0 ? `AGREE: ${real.length} entries, every field` : problems.join("\n"));
process.exit(problems.length === 0 ? 0 : 1);
