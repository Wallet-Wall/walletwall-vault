/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * PUBLICATION PROVENANCE — established EXTERNALLY, and integration-aware.
 *
 * `evidence-subject.ts` explains why an artifact cannot name the commit containing it: the
 * embedded value becomes part of the identity it is trying to state. So `SCANNER_EVIDENCE.json`
 * names exactly two commits that exist before it does -- its SOURCE SUBJECT and its
 * TRIAGE/GENERATION SUBJECT -- and the publishing commit is proven afterwards, from git.
 *
 * WHAT THE FIRST VERSION GOT WRONG. It required the commit under test to BE the publication
 * container: `HEAD^1 == triageSubject` and `diff triageSubject..HEAD == the receipt only`. That is
 * true at the publication commit and false forever after. The moment PR #181 was merged into #179
 * with an ordinary merge commit, the check failed:
 *
 *   container    c6c99478  (the merge)
 *   first parent 71aee6f3  (the #179 branch tip)
 *   expected     ada95399  (the triage subject)
 *
 * Nothing was wrong with the evidence. The receipt, the triage, the contracts tree and the scanner
 * scope were all byte-identical to the publication commit; only the assumption "current head is
 * the publication container" was wrong. Conflating the two makes every legitimate integration look
 * like tampering, and -- far worse -- would push people to skip the check on merge commits, which
 * is exactly where a silent receipt swap would hide.
 *
 * THE TWO-STAGE MODEL. Publication is a HISTORICAL FACT about one commit; currency is a LIVE FACT
 * about the head. They are proven separately.
 *
 *   STAGE 1 — ORIGINAL PUBLICATION. From the receipt's declared triage subject T, find the unique
 *   commit P reachable from the real head H such that P^1 == T and diff T..P is exactly
 *   SCANNER_EVIDENCE.json. Zero matches fails; more than one fails as AMBIGUOUS. Candidates are
 *   drawn from H's own ancestry, never from arbitrary refs: a commit whose first parent happens to
 *   be T but which no branch reaches is not this branch's publication container.
 *
 *   STAGE 2 — DESCENDANT CURRENCY. P must be an ancestor of H; the receipt bytes at H must equal
 *   those at P; the scanner-semantic input scope at H must equal both P and the declared source
 *   subject; the triage bytes at H must equal P unless an explicit supersession says otherwise.
 *
 * NOT EVIDENCE, and not consulted: ancestry alone, equal finding counts, equal tree counts, merge
 * status, filename equality. Every one of those held while the receipt was stale.
 *
 * SYNTHETIC MERGE REFS ARE NEVER AUTHORITY. On a `pull_request` event GITHUB_SHA is a synthetic
 * refs/pull/N/merge commit: trigger-dependent, reachable from no branch, recreated whenever base
 * or head moves. It may not be P, and it may not be H. Callers pass the real head; this module
 * additionally refuses a candidate P that is only reachable through such a commit, because P must
 * be an ancestor of the real head to be this branch's publication container.
 */
import { execFileSync } from "node:child_process";
import { compareScopes, scopeAt, type GitRunner, realGit } from "./scanner-input-scope.js";

export const RECEIPT_PATH = "prototype/vnext-kernel/SCANNER_EVIDENCE.json";
export const TRIAGE_PATH = "prototype/vnext-kernel/slither-triage.json";

export interface ScannerReceipt {
  schema: string;
  sourceSubject: string;
  sourceTree: string;
  triageSubject: string;
  triageTree: string;
  /** Set only when a later publication generation supersedes an earlier one for the same subject. */
  supersedesPublication?: string;
  [k: string]: unknown;
}

export interface Proof {
  step: string;
  detail: string;
}

const OBJECT_ID = /^[0-9a-f]{40}$/;

function requireOid(name: string, value: string): string {
  if (!OBJECT_ID.test(value)) throw new Error(`${name} must be a 40-hex object id, got ${JSON.stringify(value)}`);
  return value;
}

/**
 * STAGE 1. The unique publication container for T on H's ancestry.
 *
 * Candidates come from `git rev-list H` restricted to descendants of T, so a commit that exists in
 * the object store but is unreachable from the real head can never be selected.
 */
export function findPublicationContainer(
  triageSubject: string,
  head: string,
  git: GitRunner = realGit,
): { container: string; candidates: string[] } {
  requireOid("triageSubject", triageSubject);
  // Commits reachable from H that have T as an ancestor -- i.e. T's descendants on this branch.
  const reachable = git(["rev-list", "--ancestry-path", `${triageSubject}..${head}`])
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  const candidates: string[] = [];
  for (const c of reachable) {
    const parents = git(["rev-list", "--parents", "-n", "1", c]).split(/\s+/);
    if (parents[1] !== triageSubject) continue;
    const changed = git(["diff", "--name-only", triageSubject, c]).split("\n").map((s) => s.trim()).filter(Boolean);
    if (changed.length === 1 && changed[0] === RECEIPT_PATH) candidates.push(c);
  }

  if (candidates.length === 0) {
    throw new Error(
      `no publication container found for triage subject ${triageSubject} on the ancestry of ${head}: ` +
        `expected exactly one reachable commit whose first parent is ${triageSubject} and whose only ` +
        `change is ${RECEIPT_PATH}`,
    );
  }
  if (candidates.length > 1) {
    throw new Error(
      `FAIL_AMBIGUOUS: ${candidates.length} publication containers claim triage subject ${triageSubject} ` +
        `on the ancestry of ${head} (${candidates.join(", ")}). Two generations cannot both be authoritative ` +
        `for one declared subject; the later one must declare supersedesPublication.`,
    );
  }
  return { container: candidates[0], candidates };
}

/** STAGE 2. The receipt at H is still the one P published, describing the same scanner inputs. */
export function assertDescendantCurrency(
  receipt: ScannerReceipt,
  container: string,
  head: string,
  rootDir: string,
  git: GitRunner = realGit,
): Proof[] {
  const proofs: Proof[] = [];

  try {
    git(["merge-base", "--is-ancestor", container, head]);
  } catch {
    throw new Error(`publication container ${container} is not an ancestor of ${head}`);
  }
  proofs.push({ step: "container-is-ancestor-of-head", detail: `${container} .. ${head}` });

  const at = (rev: string, p: string) => git(["show", `${rev}:${p}`]);
  if (at(container, RECEIPT_PATH) !== at(head, RECEIPT_PATH)) {
    throw new Error(
      `${RECEIPT_PATH} at ${head} is not byte-identical to the copy published at ${container}; ` +
        `a descendant replaced the receipt without publishing a new container`,
    );
  }
  proofs.push({ step: "receipt-bytes-unchanged-since-publication", detail: `${RECEIPT_PATH} equal at ${container} and ${head}` });

  if (at(container, TRIAGE_PATH) !== at(head, TRIAGE_PATH)) {
    throw new Error(
      `${TRIAGE_PATH} at ${head} differs from ${container} while the receipt still claims that publication; ` +
        `an adjudication change requires a new receipt publication, not an inherited one`,
    );
  }
  proofs.push({ step: "triage-semantics-unchanged-since-publication", detail: `${TRIAGE_PATH} equal at ${container} and ${head}` });

  const declared = scopeAt(receipt.sourceSubject, rootDir, git);
  for (const [label, rev] of [["publication container", container], ["head", head]] as const) {
    const { equal, differences } = compareScopes(declared, scopeAt(rev, rootDir, git));
    if (!equal) {
      throw new Error(
        `scanner-input scope at ${label} ${rev} differs from the declared source subject ${receipt.sourceSubject}:\n  ` +
          differences.join("\n  "),
      );
    }
  }
  proofs.push({ step: "scanner-scope-equal-source-container-head", detail: `contractsTree ${declared.contractsTree}` });

  return proofs;
}

/** The receipt's declared subjects must resolve and be what they say they are. */
export function assertDeclaredSubjectsTruthful(receipt: ScannerReceipt, git: GitRunner = realGit): Proof {
  for (const [name, head, tree] of [
    ["sourceSubject", receipt.sourceSubject, receipt.sourceTree],
    ["triageSubject", receipt.triageSubject, receipt.triageTree],
  ] as const) {
    requireOid(`${name}.head`, head);
    requireOid(`${name}.tree`, tree);
    const actual = git(["rev-parse", `${head}^{tree}`]);
    if (actual !== tree) throw new Error(`${name}: declared tree ${tree} is not the tree of ${head} (${actual})`);
  }
  return { step: "declared-subjects-truthful", detail: `${receipt.sourceSubject} / ${receipt.triageSubject}` };
}

/**
 * Refuses a receipt that names its own publication container.
 *
 * By VALUE here; `generate-scanner-evidence.ts` refuses the container-shaped field NAMES. Neither
 * subsumes the other: the name rule stops a field being added to hold it, the value rule stops an
 * oid smuggled into an innocuous one.
 */
export function assertReceiptDoesNotNameContainer(receiptText: string, container: string): Proof {
  requireOid("container", container);
  if (receiptText.includes(container)) {
    throw new Error(
      `receipt names its own publication container ${container}; the container is established ` +
        `externally by git ancestry and delta, and an artifact embedding its own container id is circular`,
    );
  }
  return { step: "receipt-does-not-name-container", detail: `${container} absent from receipt bytes` };
}

export interface VerificationResult {
  head: string;
  container: string;
  proofs: Proof[];
}

/**
 * Full verification for an integration head.
 *
 * `head` must be a REAL branch head. A synthetic refs/pull/N/merge commit passed here would fail
 * Stage 1 on its own terms -- no reachable child of T on that ancestry publishes only the receipt
 * unless the real publication commit is itself reachable, in which case the real P is found and
 * the synthetic commit is never selected as P.
 */
export function verifyPublicationProvenance(head: string, rootDir: string, git: GitRunner = realGit): VerificationResult {
  const resolvedHead = requireOid("head", git(["rev-parse", head]));
  const receiptText = git(["show", `${resolvedHead}:${RECEIPT_PATH}`]);
  const receipt = JSON.parse(receiptText) as ScannerReceipt;

  const proofs: Proof[] = [assertDeclaredSubjectsTruthful(receipt, git)];
  const { container } = findPublicationContainer(receipt.triageSubject, resolvedHead, git);
  proofs.push({ step: "publication-container-located", detail: `${container} (unique child of ${receipt.triageSubject} changing only the receipt)` });
  proofs.push(...assertDescendantCurrency(receipt, container, resolvedHead, rootDir, git));
  proofs.push(assertReceiptDoesNotNameContainer(receiptText, container));

  return { head: resolvedHead, container, proofs };
}

if (process.argv[1] && process.argv[1].endsWith("verify-receipt-container.ts")) {
  const head = process.argv[2];
  if (!head) {
    console.error("usage: tsx prototype/vnext-kernel/verify-receipt-container.ts <real-branch-head-oid>");
    console.error("Pass the REAL head. On a pull_request event GITHUB_SHA is a synthetic merge commit and is not authority.");
    process.exit(2);
  }
  const resolved = execFileSync("git", ["rev-parse", head], { encoding: "utf8" }).trim();
  const result = verifyPublicationProvenance(resolved, ".");
  for (const p of result.proofs) console.log(`  OK  ${p.step}: ${p.detail}`);
  console.log(`head ${result.head} verified; publication container ${result.container}.`);
}
