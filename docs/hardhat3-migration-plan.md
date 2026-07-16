# Hardhat 2 → 3 Migration Implementation Plan (walletwall-vault)

> **For agentic workers:** implement task-by-task; each task ends at a named CI gate that must pass locally before moving on. Steps use checkbox (`- [ ]`) syntax. This is executed **inline** (not subagent-driven): the phases are strictly sequential and each is verified by running the real toolchain (`npm install` / `hardhat compile` / `npm test`) in one shared worktree, so fan-out would only cause node_modules races.

**Goal:** Migrate `walletwall-vault` from Hardhat 2 (`^2.22.15`, ts-node/CommonJS) to Hardhat 3 (`^3.9.1`, ESM), which unblocks the deferred `@nomicfoundation/*` major set, `chai@6`, and (separately, later) `typescript@7`. Delivered as ONE feature-branch PR, verified green locally against the full CI gate, **never merged without explicit per-repo approval**.

**Architecture:** HH3 is an ESM-first, plugin-explicit rewrite. Three structural changes drive everything: (1) the project becomes an ES module (`"type":"module"`); (2) the global `import { ethers } from "hardhat"` HRE singleton is replaced by an explicit per-connection object `const { ethers } = await network.connect()`; (3) plugins are declared in a `plugins: []` array via `defineConfig` instead of side-effect imports. ts-node is dropped — standalone TS scripts run under `tsx` (robust) and tests/config run under Hardhat's own loader (`@nomicfoundation/hardhat-mocha`). solidity-coverage is removed in favor of HH3's built-in `hardhat test --coverage`.

**Tech Stack (target):** `hardhat@^3.9.1`, `@nomicfoundation/hardhat-toolbox-mocha-ethers@^3.0.7` (bundles hardhat-ethers@4, hardhat-ethers-chai-matchers@3, hardhat-network-helpers@3, hardhat-mocha@3, hardhat-typechain@3, hardhat-verify@3, hardhat-ignition@3, ignition-ethers@3, keystore@3, mocha@11, chai `>=5.1.2 <7`, ethers@^6.14), `chai@^6.2.2`, `ethers@^6.14`, `typescript@~5.6` (NOT 7 — see risk R5), `tsx` (script runner), `typechain@^8.3.2` + `@typechain/ethers-v6@^0.5.1` (generator target), `prettier` + `prettier-plugin-solidity` + `solhint` (unchanged). Node **>=22.10.0** (local dev is v24.16.0 ✓).

## Global Constraints (copied verbatim from session rules — apply to EVERY task)

- **PR-only. NEVER push to `main`.** Feature branch + PR against `Wallet-Wall/walletwall-vault`. Do not merge; merging needs explicit, per-repo `--admin` sign-off named by the user.
- **Isolated worktree, native Windows path, off `origin/main` (NOT stale local `main`).** Own `node_modules` (deps change substantially — no shared junction).
- **Do not disturb the 3 other live worktrees**, especially the Codex one at `...OneDrive\Documents\WalletWall\.codex-worktrees\walletwall-vault-no-cost-hardening`.
- **Commit author/committer email:** `sirmrdrgod@users.noreply.github.com`.
- **Version gate:** `pr-version-check.yml` fails if `package.json` `version` == `origin/main` version. `origin/main` = **0.9.27** → bump to **0.10.0** (a major-ish minor for a framework migration on a 0.x package).
- **Junction-safe teardown at the end:** `rmdir` any node_modules junction BEFORE `git worktree remove`; never recursive-delete a worktree with a junction. (This worktree uses its OWN node_modules, so no junction — but the rule stands if one is added.)
- **Honesty gate:** if a phase hits a hard blocker (a plugin genuinely unsupported on HH3, an unresolvable API cascade), STOP, report the exact error, and leave a clearly-labelled DRAFT PR — do not force broken or fake-green code.
- Closes tracking issue **#131** on merge.

**Baseline facts (verified from `origin/main` @ `5e96219`):** version 0.9.27; hardhat ^2.22.15; ts-node; typescript ^5.6.3; 18 `.sol` contracts; **22 test `.ts` files** touch `hardhat`/`hre`/`ethers`; **12 files** import `typechain-types`; **7 scripts** import from `"hardhat"`; **31 `ts-node scripts/*.ts`** npm scripts; **only 3 scripts** use CommonJS idioms (`__dirname`); `hardhat-gas-reporter` is UNUSED (no config block / `REPORT_GAS`). CI `build-test` job order: `npm ci` → `security:audit` → `compile` → `typecheck` (`tsc --noEmit`, with `pretypecheck=hardhat compile`) → `format:check` → `lint` (solhint) → `test` → smoke CLIs (`verifier:verify`, `attestor:demo`) → `sp1:smoke` → `proof:artifact:validate` → `validate:evidence` → `validate:sp1-input` → `validate:zk-adapter` → `validate:zk-response` → `validate:static-artifact` → `coverage`. CI pins **Node 20** (must become 22). Separate jobs (Rust zkVM) are unaffected.

---

### Task 0: Isolated worktree + branch

**Files:** none (git plumbing).

- [ ] **Step 1** — From `C:\dev\walletwall-vault`, fetch and create a fresh worktree off `origin/main` at a native Windows path:
  `git fetch origin` → `git worktree add -b chore/hardhat-3-migration C:\dev\wv-hardhat3 origin/main`
- [ ] **Step 2** — Verify: worktree HEAD == `origin/main` (`5e96219`), branch is `chore/hardhat-3-migration`, `package.json` version is `0.9.27`, and `dependabot.yml` HAS the ignore block (confirms non-stale baseline).
- [ ] **Step 3** — Copy this plan into the worktree at `docs/hardhat3-migration-plan.md` (ships with the PR for reviewers).

**Gate:** clean worktree on the new branch at the correct baseline.

---

### Task 1: Dependency + ESM foundation (config, tsconfig, package.json) → **compile + typechain gate**

**Files:**
- Modify: `package.json`
- Modify: `tsconfig.json`
- Rewrite: `hardhat.config.ts`
- Reference: generate a throwaway HH3 scaffold with `npx hardhat@3 --init` in a temp dir to copy the canonical `package.json`/`tsconfig.json`/`hardhat.config.ts` shape, then adapt (don't hand-invent ESM settings).

**Interfaces produced (later tasks rely on these):**
- Config exports `defineConfig({ plugins:[hardhatToolboxMochaEthers], solidity:{...}, networks:{...} })`.
- Network access everywhere else: `import { network } from "hardhat"; const conn = await network.connect(<name?>); const { ethers } = conn;`
- typechain types remain at `typechain-types/` (import path unchanged: `../../typechain-types`).

- [ ] **Step 1: `package.json` — remove HH2 toolchain.** Delete: `@nomicfoundation/hardhat-chai-matchers`, `@nomicfoundation/hardhat-ethers`, `@nomicfoundation/hardhat-ignition`, `@nomicfoundation/hardhat-ignition-ethers`, `@nomicfoundation/hardhat-network-helpers`, `@nomicfoundation/hardhat-toolbox`, `@nomicfoundation/hardhat-verify`, `@nomicfoundation/ignition-core`, `@typechain/hardhat`, `hardhat`, `hardhat-gas-reporter`, `solidity-coverage`, `ts-node`. Keep `@typechain/ethers-v6`, `typechain`, `@openzeppelin/contracts`, `ethers`, `prettier`, `prettier-plugin-solidity`, `solhint`, `@noble/post-quantum`, `dotenv`.
- [ ] **Step 2: `package.json` — add HH3 toolchain.** Add devDeps: `"hardhat": "^3.9.1"`, `"@nomicfoundation/hardhat-toolbox-mocha-ethers": "^3.0.7"`, `"chai": "^6.2.2"`, `"tsx": "^4.19.2"` (verify latest at install). Bump `"ethers"` to `^6.14.0`. Drop `@types/chai`/`@types/mocha` if the toolbox supplies types (verify during typecheck; re-add if `tsc` complains).
- [ ] **Step 3: `package.json` — ESM + engines + version + scripts.** Add `"type": "module"`; add `"engines": { "node": ">=22.10.0" }`; bump `"version": "0.10.0"`. Rewrite scripts: `"coverage": "hardhat test --coverage"` (was `hardhat coverage`); replace every `ts-node scripts/X.ts` with `tsx scripts/X.ts` (all ~24 CLI/validator/fixture scripts); `deploy`/`demo`/`deploy:simulator` etc. stay `hardhat run scripts/X.ts` (verify `hardhat run` semantics during Task 2); `typecheck` stays `tsc --noEmit`; `pretypecheck` stays `hardhat compile`.
- [ ] **Step 4: `tsconfig.json` — ESM.** Set `"module": "esnext"`, `"moduleResolution": "bundler"` (KEY: avoids `.js`-extension churn), `"target": "es2022"`, keep `"strict"`, `"esModuleInterop"`, `"skipLibCheck"`, `"forceConsistentCasingInFileNames"`, `"resolveJsonModule": true`. Drop `"outDir"/"rootDir"` if unused by build. Keep `include` (`src, scripts, test, pqc, hardhat.config.ts, typechain-types`). Remove any `ts-node` block.
- [ ] **Step 5: `hardhat.config.ts` — HH3 rewrite.** Exact target:
```ts
import "dotenv/config";
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
const accounts = deployerKey ? [deployerKey] : [];

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.24",
    settings: { evmVersion: "cancun", optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    // NOTE: exact HH3 network schema (type: "http" / "edr-simulated", chainType,
    // accounts shape) to be confirmed against the init scaffold in this task.
    sepolia: { type: "http", url: process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com", accounts },
    "base-sepolia": { type: "http", url: process.env.BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org", accounts },
  },
});
```
  (`localhost` becomes an `http` network or is dropped in favor of the default in-process `edr-simulated` network — decide from the init scaffold.)
- [ ] **Step 6: install.** `npm install` in the worktree. Then `npm why hardhat` must show only `hardhat@3.x`. Fix peer-dep complaints.
- [ ] **Step 7: compile gate.** `npm run compile` — must (a) compile all 18 contracts under solc 0.8.24/cancun and (b) regenerate `typechain-types/` via `@nomicfoundation/hardhat-typechain`. Confirm `typechain-types/index.ts` exists and exports `WalletWallVault` etc.
- [ ] **Step 8: commit.** `git add -A && git commit -m "chore(vault): Hardhat 3 ESM foundation — deps, tsconfig, config"`

**Gate:** `npm run compile` green + typechain types generated. (`tsc --noEmit` will still fail here — expected until Tasks 2–4.)

---

### Task 2: Migrate the 7 hardhat-using scripts → contributes to **typecheck gate**

**Files (Modify):** `scripts/deploy.ts`, `scripts/deploy-simulator.ts`, `scripts/demo-simulator.ts`, `scripts/propose-verifier-update.ts`, `scripts/deploy-zk-verifier.ts`, `scripts/demo-sign-attestation-unsafe.ts`, `scripts/demo-local.ts`.

**Transformation recipe (apply per file):**
- Replace `import { ethers, network } from "hardhat";` with `import { network } from "hardhat";` and, inside `main()`, `const connection = await network.connect(); const { ethers } = connection;`.
- Replace uses of the old global `network.name` with the connection's network identity (`connection.networkName` — confirm exact prop from HH3 types during edit).
- All `ethers.*` calls (`getSigners`, `getContractFactory`, `getContractAt`, `provider`, `Wallet`, `isAddress`, `TypedDataEncoder`, …) work unchanged on the connection's `ethers`.
- Fix `__dirname` (in `deploy-simulator.ts`) → `import.meta.dirname` (Node 22.10+/24 native).

- [ ] **Step 1:** Apply recipe to `scripts/deploy.ts` (worked reference — it uses `network.name`, `ethers.provider.getNetwork()`, `getSigners`, `getContractFactory`, `getContractAt`, `Wallet`, `isAddress`). Preserve ALL mainnet/chain-id guard logic byte-for-byte; only the ethers/network acquisition changes.
- [ ] **Step 2:** Apply recipe to the other 6 scripts.
- [ ] **Step 3:** `tsc --noEmit` — the 7 scripts must now typecheck (test files will still error until Task 4).
- [ ] **Step 4: commit.** `git commit -m "chore(vault): port deploy/demo scripts to HH3 network.connect()"`

**Gate:** the 7 scripts typecheck clean; guard logic unchanged.

---

### Task 3: Migrate standalone TS scripts to tsx/ESM → **CI smoke/validator gates**

**Files (Modify):** the ~17 non-hardhat CLI/validator/fixture scripts run via npm scripts, notably the **9 CI-gated** ones: `scripts/pq-verifier-cli.ts` (`verifier:verify`), `scripts/attestor-cli.ts` (`attestor:demo`), `scripts/sp1-smoke.ts`, `scripts/generate-proof-artifact.ts` (`--validate`), `scripts/generate-mldsa-evidence-manifest.ts` (`--validate`), `scripts/generate-sp1-proof-input.ts` (`--validate`), `scripts/generate-zk-verifier-adapter.ts` (`--validate`), `scripts/generate-zk-adapter-evidence-response.ts` (`--validate`), `scripts/generate-static-evidence-artifact.ts` (`--validate`). Plus `validate-reproducibility.ts`, `validate-deployments.ts` (CommonJS idioms).

**Transformation recipe:**
- These are pure TS (crypto + fs + JSON); most already use `import`. Under `"type":"module"` + `tsx`, they run as ESM.
- Fix `__dirname`/`__filename` → `import.meta.dirname` / `fileURLToPath(import.meta.url)` (2 files: `validate-reproducibility.ts`, `validate-deployments.ts`).
- Fix any `require(...)`/`module.exports`/`export =` → ESM `import`/`export`.
- Ensure JSON imports use `import ... assert { type: "json" }` OR `fs.readFileSync` (prefer existing fs pattern; avoid import assertions churn).

- [ ] **Step 1:** Run each CI-gated script under tsx and fix ESM breakage one at a time:
  `npm run verifier:verify -- --message-file test/fixtures/mldsa/library-generated/message.hex --public-key-file .../public-key.hex --pq-signature-file .../signature.hex --json` → assert output contains `"reason": "ML_DSA_65_VALID"`.
  `npm run attestor:demo` → runs clean.
  `npm run sp1:smoke` → output has `"mode": "sp1-smoke"`, `"proven": false`, `"hostExecuted": false`.
  `npm run proof:artifact:validate`, `npm run validate:evidence`, `npm run validate:sp1-input`, `npm run validate:zk-adapter`, `npm run validate:zk-response`, `npm run validate:static-artifact` → each exits 0.
- [ ] **Step 2:** Fix the 2 CommonJS-idiom scripts + any other npm-script tsx runner that errors.
- [ ] **Step 3: commit.** `git commit -m "chore(vault): run standalone TS scripts under tsx (ESM)"`

**Gate:** all 9 CI-gated script commands reproduce their asserted output byte-compatibly.

---

### Task 4: Migrate test helpers + 22 test files → **`npm test` gate** (the big one)

**Files (Modify):** `test/helpers/vaultHelpers.ts`, `test/helpers/simulatorHelpers.ts`, `test/helpers/zkVerifierHelpers.ts`, and the 22 `test/*.test.ts` files listed in the baseline.

**Core problem + strategy:** helpers use module-level `import { ethers } from "hardhat"` and `import { time } from "@nomicfoundation/hardhat-network-helpers"`. In HH3 both come from a per-test connection. Strategy: **thread the connection's `ethers` (and `networkHelpers`) as parameters** into helper functions, and in each test suite create ONE connection in a `before()` hook and reuse it.

**Per-test-file recipe:**
```ts
// before:  import { ethers } from "hardhat";  // (+ helpers used the global)
// after:
import { network } from "hardhat";
import { expect } from "chai";
// ...
describe("Suite", () => {
  let ethers: Awaited<ReturnType<typeof network.connect>>["ethers"];
  let networkHelpers: Awaited<ReturnType<typeof network.connect>>["networkHelpers"];
  before(async () => { ({ ethers, networkHelpers } = await network.connect()); });
  // use `ethers` and `networkHelpers.time`/`.mine`/`.loadFixture` in tests;
  // pass `ethers` into helpers that need it.
});
```
**Helper recipe (`vaultHelpers.ts` worked example):** drop `import { ethers } from "hardhat"` and `import { time } ...`; add `ethers` (typed `HardhatEthers`) and, where needed, `time`/`networkHelpers` as function params:
```ts
export async function withdrawalDomain(ethers, vault: WalletWallVault) { /* uses ethers.provider */ }
export function makeSignWithdrawal(ethers, vault, signer) { /* uses ethers.hexlify/concat/randomBytes */ }
export function makeBuildRequest(networkHelpers, owner, defaults) { /* uses networkHelpers.time.latest() */ }
```
  (`SignerWithAddress` import path becomes `@nomicfoundation/hardhat-ethers/signers` under v4 — confirm during typecheck.)

**chai-matchers API changes (apply at call sites):** `.reverted` → `.revert(ethers)`; `.revertedWithoutReason()` → `.revertedWithoutReason(ethers)`; `changeEtherBalance(s)` / `changeTokenBalance(s)` now take the `ethers` (HardhatEthers) instance as the FIRST argument. `loadFixture` comes from `networkHelpers.loadFixture` (not the standalone import).

- [ ] **Step 1:** Migrate the 3 helpers first (they're the shared dependency). Typecheck helpers in isolation where possible.
- [ ] **Step 2:** Migrate test files in dependency order, running the suite incrementally: start with a small one (`test/MockUSDC.test.ts`), get it green, then proceed. Run `npm test -- --grep <suite>` or a single file to iterate fast.
- [ ] **Step 3:** Full `npm test` — all suites green. Watch for: fixture/snapshot reuse across connections, and any test that assumed a fresh chain per `it` (HH3 connection semantics).
- [ ] **Step 4:** `tsc --noEmit` now fully clean (contracts + scripts + tests).
- [ ] **Step 5: commit.** `git commit -m "test(vault): migrate mocha+ethers suite to HH3 connections + chai 6 matchers"`

**Gate:** `npm test` all green AND `npm run typecheck` clean.

---

### Task 5: format + lint + coverage gates

**Files:** none (verification) or minor `.prettierrc`/`.solhint` if ESM trips them.

- [ ] **Step 1:** `npm run format:check` — prettier on `.sol` + `{src,scripts,test,pqc}/**/*.ts`. Run `npm run format` to normalize if the migration changed formatting; re-run check.
- [ ] **Step 2:** `npm run lint` — solhint on contracts (unaffected by JS toolchain; should pass unchanged).
- [ ] **Step 3:** `npm run coverage` (= `hardhat test --coverage`) — confirm it runs and writes `coverage/lcov.info` + `coverage/html/index.html`. If `.gitignore` needs `coverage/`, verify it's already ignored.
- [ ] **Step 4: commit** (only if files changed) `git commit -m "chore(vault): formatting + coverage under HH3"`

**Gate:** format:check, lint, coverage all green.

---

### Task 6: CI + publish workflows + dependabot

**Files (Modify):** `.github/workflows/ci.yml`, `.github/workflows/publish-static-evidence.yml`, `.github/dependabot.yml`.

- [ ] **Step 1: `ci.yml`** — `setup-node` `node-version: "20"` → `"22"`. The step commands are unchanged (they call npm scripts, which now map to HH3). Keep everything else. (`security:audit` unaffected; `coverage` step already `npm run coverage`.)
- [ ] **Step 2: `publish-static-evidence.yml`** — `node-version: "20"` → `"22"` (its `npm ci` installs HH3 which needs 22.10+; its validate scripts run under tsx).
- [ ] **Step 3: `dependabot.yml`** — update the npm `ignore:` block: **remove** the `chai` major-ignore (now on chai 6) and the `hardhat-gas-reporter` ignore (package removed); **keep** `hardhat` + `@nomicfoundation/*` major-ignores (defer a future HH4 the same way) and the `typescript` major-ignore (TS7 still lacks the classic compiler API that `typechain` needs — see R5). Update the comment to say the repo is now ON Hardhat 3.
- [ ] **Step 4: commit.** `git commit -m "ci(vault): Node 22 for HH3; refresh dependabot majors policy"`

**Gate:** workflows reference Node 22; dependabot policy coherent with HH3 baseline.

---

### Task 7: Full local CI dry-run → PR

- [ ] **Step 1:** Re-run the ENTIRE `build-test` job sequence locally in order (audit → compile → typecheck → format:check → lint → test → all 9 smoke/validator commands → coverage). All green.
- [ ] **Step 2:** `git push -u origin chore/hardhat-3-migration`.
- [ ] **Step 3:** Open PR against `Wallet-Wall/walletwall-vault` main. Body: what changed, the CI-gate dry-run results, the honest risk notes, "Closes #131", and an explicit "DO NOT MERGE until you review — I have not merged." Mark **ready** (not draft) IF fully green; leave **draft** with a status table if any gate is red.
- [ ] **Step 4:** Report to user: PR link, per-gate local status, residual risks. Do NOT merge.

**Gate:** PR open, CI running, honest status reported.

---

## Risk Register (honest)

- **R1 — Test API cascade (highest effort):** 22 files + 3 helpers move to per-connection `ethers` + changed chai-matcher signatures. Mitigation: migrate helpers once, thread params, iterate suite-by-suite. If a matcher/fixture behavior differs materially, fix per-site; do not blanket-suppress.
- **R2 — `hardhat run` semantics for deploy scripts:** HH3 may run scripts differently than HH2's `hardhat run --network`. Resolve empirically (`npx hardhat run --help`) in Task 2; deploy scripts are NOT in the CI gate (no live deploy in CI), so this can't red CI, but must be correct for real use.
- **R3 — tsx JSON/`import.meta` edge cases** in the 9 gated scripts. Resolve per-script in Task 3 against real fixture output.
- **R4 — `@types/chai`/`@types/mocha` under ESM + chai 6:** chai 6 ships types; re-add `@types/*` only if `tsc` demands. 
- **R5 — TypeScript 7 stays deferred:** HH3 removes ts-node, but `typechain` still calls the classic TS compiler API that TS7 dropped → TS7 would break `hardhat-typechain`. This migration lands on TS 5.6; TS7 remains a separate future task. Keep its dependabot major-ignore.
- **R6 — Node 22 in CI:** hard requirement; both workflows bumped. If any CI action mis-resolves "22", pin `22.x`.
- **STOP conditions:** a bundled plugin genuinely fails to load on HH3, or the test cascade proves unresolvable within reason → stop, leave a labelled DRAFT PR with the exact failure, report honestly.

## Self-Review (spec coverage)

- Deps overhaul → T1. ESM (`type:module`, tsconfig) → T1. Config rewrite → T1. `hardhat run`/network scripts → T2. 31 ts-node→tsx scripts + CI-gated CLIs → T3. 22 tests + helpers + chai6 → T4. coverage/format/lint → T5. Node-22 CI + publish + dependabot → T6. Version bump 0.9.27→0.10.0 → T1/global. Close #131 → T7. Every CI `build-test` step maps to a gate in T1/T3/T4/T5/T7. Rust jobs untouched (correctly out of scope).
