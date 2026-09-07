/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * PUBLICATION CONTAINER VERIFICATION — established EXTERNALLY, never self-declared.
 *
 * `evidence-subject.ts` explains why an artifact cannot name the commit that contains it: the
 * embedded value becomes part of the identity it is trying to state. That argument forbids more
 * than stamping `HEAD`; it forbids the receipt naming its container AT ALL, under any field name.
 *
 * So `SCANNER_EVIDENCE.json` names exactly two commits, both of which exist BEFORE it does:
 *
 *   sourceSubject   the commit whose scanner-semantic inputs were analyzed
 *   triageSubject   the commit whose triage file the findings were adjudicated against
 *
 * The container is whatever commit ends up holding the file. It is proven AFTERWARDS, from git,
 * by the caller supplying the container id from outside the artifact — which is the whole point:
 * the id comes from the repository, not from the bytes being verified.
 *
 * `assertReceiptDoesNotNameContainer` is the load-bearing one. It is not a style check. A receipt
 * that names its own container is either wrong (it was generated before that commit existed and
 * guessed) or circular (its content determines the id it claims). Both are unfalsifiable claims,
 * so they are refused.
 */
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { compareScopes, scopeAt, type GitRunner, realGit } from "./scanner-input-scope.js";

export const RECEIPT_PATH = "prototype/vnext-kernel/SCANNER_EVIDENCE.json";

export interface ScannerReceipt {
  schema: string;
  sourceSubject: string;
  sourceTree: string;
  triageSubject: string;
  triageTree: string;
  [k: string]: unknown;
}

export interface ContainerProof {
  step: string;
  ok: boolean;
  detail: string;
}

const OBJECT_ID = /^[0-9a-f]{40}$/;

/**
 * PROOF 5. Refuses a receipt that names its own container anywhere in its serialized bytes.
 *
 * Scans for the container id as a SUBSTRING of the serialized receipt rather than checking a list
 * of known fields, because a future field could reintroduce the defect under a new name. Naming
 * the SOURCE or TRIAGE subject stays legal — those are not the container — so this discriminates
 * rather than rejecting every object id it meets.
 */
export function assertReceiptDoesNotNameContainer(receiptText: string, containerOid: string): ContainerProof {
  if (!OBJECT_ID.test(containerOid)) throw new Error(`container oid must be a 40-hex object id, got ${containerOid}`);
  const found = receiptText.includes(containerOid);
  if (found) {
    throw new Error(
      `receipt names its own publication container ${containerOid}; the container is established ` +
        `externally by git ancestry and delta, and an artifact that embeds its own container id is circular`,
    );
  }
  return { step: "receipt-does-not-name-container", ok: true, detail: `${containerOid} absent from receipt bytes` };
}

/** PROOF 1. The container's FIRST parent is the triage subject. */
export function assertFirstParentIsTriageSubject(containerOid: string, triageSubject: string, git: GitRunner = realGit): ContainerProof {
  const parents = git(["rev-list", "--parents", "-n", "1", containerOid]).split(/\s+/);
  const firstParent = parents[1];
  if (firstParent !== triageSubject) {
    throw new Error(`container ${containerOid} first parent is ${firstParent}, expected triage subject ${triageSubject}`);
  }
  return { step: "first-parent-is-triage-subject", ok: true, detail: `${containerOid}^1 == ${triageSubject}` };
}

/** PROOF 2. The container changes the receipt and nothing else. */
export function assertContainerChangesReceiptOnly(triageSubject: string, containerOid: string, git: GitRunner = realGit): ContainerProof {
  const changed = git(["diff", "--name-only", triageSubject, containerOid]).split("\n").map((s) => s.trim()).filter(Boolean);
  const unexpected = changed.filter((p) => p !== RECEIPT_PATH);
  if (changed.length === 0) throw new Error(`container ${containerOid} changes nothing relative to ${triageSubject}`);
  if (unexpected.length > 0) {
    throw new Error(`container ${containerOid} changes files other than ${RECEIPT_PATH}: ${unexpected.join(", ")}`);
  }
  return { step: "container-changes-receipt-only", ok: true, detail: changed.join(", ") };
}

/** PROOF 3. Scanner-semantic inputs are equal across sourceSubject -> triageSubject -> container. */
export function assertScopeCurrency(
  sourceSubject: string,
  triageSubject: string,
  containerOid: string,
  rootDir: string,
  git: GitRunner = realGit,
): ContainerProof {
  const source = scopeAt(sourceSubject, rootDir, git);
  for (const [label, rev] of [["triageSubject", triageSubject], ["container", containerOid]] as const) {
    const { equal, differences } = compareScopes(source, scopeAt(rev, rootDir, git));
    if (!equal) {
      throw new Error(`scanner-input scope differs between sourceSubject ${sourceSubject} and ${label} ${rev}:\n  ${differences.join("\n  ")}`);
    }
  }
  return { step: "scope-currency", ok: true, detail: `contractsTree ${source.contractsTree} equal across all three` };
}

/** PROOF 4. The receipt's declared subjects resolve and are what it says they are. */
export function assertDeclaredSubjectsTruthful(receipt: ScannerReceipt, git: GitRunner = realGit): ContainerProof {
  const pairs: Array<[string, string, string]> = [
    ["sourceSubject", receipt.sourceSubject, receipt.sourceTree],
    ["triageSubject", receipt.triageSubject, receipt.triageTree],
  ];
  for (const [name, head, tree] of pairs) {
    if (!OBJECT_ID.test(head) || !OBJECT_ID.test(tree)) throw new Error(`${name}: head/tree must be 40-hex object ids`);
    const actualTree = git(["rev-parse", `${head}^{tree}`]);
    if (actualTree !== tree) throw new Error(`${name}: declared tree ${tree} is not the tree of ${head} (${actualTree})`);
  }
  return { step: "declared-subjects-truthful", ok: true, detail: `${receipt.sourceSubject} / ${receipt.triageSubject}` };
}

export function verifyContainer(containerOid: string, rootDir: string, git: GitRunner = realGit): ContainerProof[] {
  const receiptText = git(["show", `${containerOid}:${RECEIPT_PATH}`]);
  const receipt = JSON.parse(receiptText) as ScannerReceipt;
  return [
    assertDeclaredSubjectsTruthful(receipt, git),
    assertFirstParentIsTriageSubject(containerOid, receipt.triageSubject, git),
    assertContainerChangesReceiptOnly(receipt.triageSubject, containerOid, git),
    assertScopeCurrency(receipt.sourceSubject, receipt.triageSubject, containerOid, rootDir, git),
    assertReceiptDoesNotNameContainer(receiptText, containerOid),
  ];
}

if (process.argv[1] && process.argv[1].endsWith("verify-receipt-container.ts")) {
  const containerOid = process.argv[2];
  if (!containerOid) {
    console.error("usage: tsx prototype/vnext-kernel/verify-receipt-container.ts <container-commit-oid>");
    console.error("The container id is supplied from OUTSIDE the artifact on purpose; the receipt never names it.");
    process.exit(2);
  }
  const resolved = execFileSync("git", ["rev-parse", containerOid], { encoding: "utf8" }).trim();
  for (const p of verifyContainer(resolved, ".")) console.log(`  OK  ${p.step}: ${p.detail}`);
  console.log(`container ${resolved} verified against its declared subjects.`);
}

void fs;
