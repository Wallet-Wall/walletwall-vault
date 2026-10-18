/**
 * A read-only census of every tar entry in an SP1 circuit archive (scripts/lib/sp1-circuit-archive-census.ts).
 *
 *   npm run sp1:circuit-archive:census -- --archive <file.tar.gz>
 *
 * Lists every entry (type, names, mode, owner, time, size, PAX records, data sha256), decodes each AppleDouble-shaped
 * entry and reports how it relates to every other entry. Accepts nothing and installs nothing: it is the observation a
 * metadata policy is derived from, never an inspection. Prints JSON that depends only on the archive's bytes.
 *
 * Reads only the archive: no network, no download, no SP1, no tar(1). Research prototype. Not audited.
 */
import { censusArchive } from "./lib/sp1-circuit-archive-census";
import { runScript } from "./lib/run-script";

runScript(async () => {
  const i = process.argv.indexOf("--archive");
  const archive = i === -1 ? undefined : process.argv[i + 1];
  if (!archive) throw new Error("--archive is required");
  console.log(JSON.stringify(await censusArchive(archive), null, 2));
});
