import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * SP1 pin-parity gate — the three SP1 crates must declare ONE exact release.
 *
 *   zkvm/guest/Cargo.toml   [dependencies]        sp1-zkvm
 *   zkvm/host/Cargo.toml    [dependencies]        sp1-sdk
 *   zkvm/host/Cargo.toml    [build-dependencies]  sp1-build
 *                                   |
 *                    all three exact-pinned and equal
 *                                   |
 *                    any drift  =>  this gate fails
 *
 * The invariant is stated in zkvm/host/Cargo.toml: "If you bump one, bump all
 * three together, then re-extract the program vKey."
 *
 * WHY A GATE AND NOT JUST A DEPENDABOT IGNORE. Ignoring `sp1-*` in
 * .github/dependabot.yml stops the automated split bump (#150 moved only the
 * guest), but it constrains only Dependabot — a human, an agent, or a script can
 * still edit one pin. Nothing else would notice: zkvm/host is deliberately
 * outside CI, "Validate SP1 host Cargo.lock" checks that lockfile's internal
 * consistency and never guest-vs-host parity, the TS<->Rust differential test is
 * skipped, and no ELF or vKey is committed whose drift would expose it.
 *
 * SCOPE, STATED PLAINLY. This proves the three DECLARED releases match and are
 * exact. It does NOT prove the declared release builds, executes, or proves
 * correctly — that needs `sp1up`, a guest rebuild, and vKey re-extraction, which
 * remain a maintainer procedure (docs/ZK_Prover_Runbook.md). This gate is pure
 * text inspection: no toolchain, no cargo, no network.
 */

/** The crates the invariant governs, and where each is declared. */
export const SP1_PINNED_CRATES: Array<{ crate: string; manifest: string; section: string }> = [
  { crate: "sp1-zkvm", manifest: "zkvm/guest/Cargo.toml", section: "dependencies" },
  { crate: "sp1-sdk", manifest: "zkvm/host/Cargo.toml", section: "dependencies" },
  { crate: "sp1-build", manifest: "zkvm/host/Cargo.toml", section: "build-dependencies" },
];

export interface Sp1ParityResult {
  ok: boolean;
  errors: string[];
  /** What was actually found, for reporting. `version` is null when undeclared. */
  pins: Array<{ crate: string; manifest: string; section: string; spec: string | null; version: string | null }>;
}

/** An exact pin: `=MAJOR.MINOR.PATCH` and nothing looser. */
const EXACT_PIN = /^=(\d+\.\d+\.\d+)$/;

/**
 * Read one dependency's version spec out of a named TOML section.
 *
 * Comment lines are stripped first: zkvm/host/Cargo.toml names `sp1-sdk` and
 * `sp1-build` in a prose comment, and a reader that matched anywhere in the file
 * would accept that prose as a declaration.
 */
function readSpec(toml: string, section: string, crate: string): string | null {
  const lines = toml.split("\n").map((l) => l.replace(/^\s*#.*$/, ""));
  let inSection = false;
  for (const line of lines) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      inSection = header[1].trim() === section;
      continue;
    }
    if (!inSection) continue;
    // `crate = "=6.3.1"` or `crate = { version = "=6.3.1", features = [...] }`
    const assign = new RegExp(`^\\s*${crate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=\\s*(.+?)\\s*$`).exec(line);
    if (!assign) continue;
    const value = assign[1];
    const bare = /^"([^"]*)"/.exec(value);
    if (bare) return bare[1];
    const table = /version\s*=\s*"([^"]*)"/.exec(value);
    if (table) return table[1];
    return value; // present but unrecognised shape — reported as not-exact below
  }
  return null;
}

export function checkSp1PinParity(inputs: { guestToml: string; hostToml: string }): Sp1ParityResult {
  const byManifest: Record<string, string> = {
    "zkvm/guest/Cargo.toml": inputs.guestToml,
    "zkvm/host/Cargo.toml": inputs.hostToml,
  };
  const errors: string[] = [];

  const pins = SP1_PINNED_CRATES.map(({ crate, manifest, section }) => {
    const spec = readSpec(byManifest[manifest] ?? "", section, crate);
    let version: string | null = null;
    if (spec === null) {
      errors.push(
        `${manifest} [${section}]: ${crate} is not declared — the SP1 pin-parity invariant requires all three of ` +
          `${SP1_PINNED_CRATES.map((c) => c.crate).join(", ")} to be present and exact-pinned.`,
      );
    } else {
      const exact = EXACT_PIN.exec(spec);
      if (!exact) {
        errors.push(
          `${manifest} [${section}]: ${crate} = "${spec}" is not an exact pin. ` +
            `Use "=MAJOR.MINOR.PATCH" (e.g. "=6.3.1"): a range can resolve to a different SP1 release at build ` +
            `time, which breaks guest/host parity by a slower route even when all three specs look identical.`,
        );
      } else {
        version = exact[1];
      }
    }
    return { crate, manifest, section, spec, version };
  });

  // Parity across whatever resolved to a real exact version.
  const resolved = pins.filter((p) => p.version !== null);
  const distinct = [...new Set(resolved.map((p) => p.version as string))];
  if (distinct.length > 1) {
    const shown = resolved.map((p) => `${p.crate}=${p.version} (${p.manifest} [${p.section}])`).join(", ");
    errors.push(
      `SP1 pins disagree: ${shown}. zkvm/host/Cargo.toml requires sp1-zkvm, sp1-sdk and sp1-build to name the ` +
        `SAME release — "If you bump one, bump all three together, then re-extract the program vKey." ` +
        `Bump all three, rebuild the guest, and re-extract the vKey per docs/ZK_Prover_Runbook.md.`,
    );
  }

  return { ok: errors.length === 0, errors, pins };
}

/**
 * Read the two real manifests this gate governs.
 *
 * Kept separate from {@link checkSp1PinParity} so the checker itself stays
 * filesystem-free and can be driven with synthetic manifests — that is what lets
 * the tests mutate one pin at a time without touching the repo's real files.
 */
export function readSp1Manifests(repoRoot: string): { guestToml: string; hostToml: string } {
  return {
    guestToml: readFileSync(join(repoRoot, "zkvm", "guest", "Cargo.toml"), "utf8"),
    hostToml: readFileSync(join(repoRoot, "zkvm", "host", "Cargo.toml"), "utf8"),
  };
}
