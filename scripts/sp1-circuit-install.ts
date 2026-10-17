/**
 * Installs a verified SP1 Groth16 circuit archive (scripts/lib/sp1-circuit-install.ts), for designation d1.
 *
 *   npm run sp1:circuit-install -- --archive <file.tar.gz> --record <record.json> --destination-root <absolute dir>
 *
 * The record must be a production record: a file directly in evidence/zk/sp1-impl/proving-archives (none exists
 * yet; an acquisition lane creates one from measured bytes), exactly as committed, accepted for d1. The anchor is read
 * from the committed evidence of the checkout this script lives in, never from the working directory. The archive is
 * installed at <destination-root>/<circuit version> only if every check passes; an existing target is refused, never
 * merged or replaced, and there is no option that changes that. Use a root that holds nothing else, and the same root
 * as the prove gate's --circuit-root.
 *
 * No network, no download, no SP1, no tar(1). Research prototype. Not audited. Testnet/local only.
 */
import { fileURLToPath } from "node:url";

import { installCircuitArchive } from "./lib/sp1-circuit-install";
import { committedProductionAnchor, committedProductionRecord } from "./lib/sp1-circuit-tooling";
import { runScript } from "./lib/run-script";

const REPO = fileURLToPath(new URL("..", import.meta.url));

function arg(name: string): string {
  const i = process.argv.indexOf(name);
  const value = i === -1 ? undefined : process.argv[i + 1];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

runScript(async () => {
  const record = committedProductionRecord(arg("--record"), REPO);
  const result = await installCircuitArchive({
    archivePath: arg("--archive"),
    record,
    anchor: committedProductionAnchor(REPO),
    destinationRoot: arg("--destination-root"),
  });
  console.log(JSON.stringify(result, null, 2));
});
