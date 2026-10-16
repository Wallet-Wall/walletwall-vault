/**
 * The WalletWall SP1 wrapper registry: an append-only fact log with build provenance (the SP1 implementation lane;
 * closes SP1-TD2 review residual R2-3; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD2 introduced the registry as a list of (chain, address) whose halt state the binding gate reads live. It now
 * records facts, numbered and appended in order, never deleted or rewritten:
 *
 *   WRAPPER_REGISTERED — a deployed wrapper: chain, address, the wrapper build it was deployed from, the designation
 *     it serves, the SP1 verifier (address, runtime code hash), PROGRAM_VKEY, the identity, the halt principal, the
 *     deployment (transaction, block, deployer), the block it was observed at, and the wrapper it replaces, if any;
 *   WRAPPER_HALTED — that wrapper's one-way halt: its transaction and block, and why.
 *
 * A wrapper's state is derived (registered → ACTIVE; a halt fact → HALTED, for good). A halted identity stays halted
 * in the record whatever any chain later says, and is refused as a registration — and, by the binding gate, as a
 * binding target — on EVERY chain: the cross-chain refusal is repository-published evidence read at deployment time,
 * not an online oracle and not a new authority (appending a halt can only refuse; nothing can remove one).
 *
 * The file keeps SP1-TD2's path. Its v1 form was an empty list; the only migration allowed is from that empty list.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getAddress, isAddress, ZeroAddress } from "ethers";

import { directoryHistoryErrors, fileHistoryErrors } from "./append-only-history";
import {
  DESIGNATIONS_DIR,
  DESIGNATION_EVIDENCE_DIR,
  identityOf,
  readDesignations,
  type ProgramDesignation,
} from "./sp1-designation";
import { WRAPPER_BUILDS_DIR, readWrapperBuilds, type WrapperBuild } from "./sp1-wrapper-build";

export const REGISTRY_REL = "evidence/zk/sp1-td2/wrapper-registry.json";
export const REGISTRY_SCHEMA = "walletwall.sp1-wrapper-registry.v2";
export const REGISTRY_V1_SCHEMA = "walletwall.sp1-wrapper-registry.v1";
export const MIGRATED_FROM = { schema: REGISTRY_V1_SCHEMA, entries: 0 } as const;
/** Why a wrapper was halted. Recorded for the reader; no reason makes a halted identity usable again. */
export const HALT_REASONS = [
  "VERIFIER_SOUNDNESS",
  "PROGRAM_SOUNDNESS",
  "WRAPPER_DEFECT",
  "PRECOMPILE_CHANGE",
  "HALT_KEY_COMPROMISE",
  "OTHER",
] as const;

export interface RegistryFact {
  seq: number;
  kind: "WRAPPER_REGISTERED" | "WRAPPER_HALTED";
  chainId: string;
  address: string;
  identity: string;
  observedAt: { block: number; blockHash: string };
  // WRAPPER_REGISTERED
  wrapperBuild?: string;
  designation?: string;
  sp1Verifier?: { address: string; runtimeCodeKeccak: string };
  programVKey?: string;
  haltPrincipal?: string;
  deployment?: { txHash: string; block: number; deployer: string };
  replaces?: { address: string } | null;
  // WRAPPER_HALTED
  reason?: string;
  halt?: { txHash: string; block: number };
}

export interface RegistryDoc {
  schema: string;
  note: string;
  migratedFrom: { schema: string; entries: number };
  facts: RegistryFact[];
}

export interface HaltRecord {
  chainId: string;
  address: string;
  seq: number;
  reason: string;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const isWord = (x: unknown) => typeof x === "string" && /^0x[0-9a-f]{64}$/.test(x);
const isChecksummed = (x: unknown) => typeof x === "string" && isAddress(x) && getAddress(x) === x;
const isBlock = (x: unknown) => Number.isInteger(x) && (x as number) >= 0;

// ---------------------------------------------------------------------------------------------------------
// What the record says
// ---------------------------------------------------------------------------------------------------------

/** The registry's own rules, without the builds and designations it names (what the binding gate checks). */
export function registryShapeErrors(doc: RegistryDoc): string[] {
  return registryErrors(doc, null, null);
}

/** The state the facts publish: registrations per chain, recorded halts, and every halt of an identity. */
export function registryState(doc: RegistryDoc) {
  const facts = Array.isArray(doc?.facts) ? doc.facts : [];
  const registrations = facts.filter((f) => f.kind === "WRAPPER_REGISTERED");
  const halts = facts.filter((f) => f.kind === "WRAPPER_HALTED");
  return {
    registeredOn: (chainId: string) => registrations.filter((f) => f.chainId === chainId).map((f) => f.address),
    registration: (chainId: string, address: string) =>
      registrations.find((f) => f.chainId === chainId && f.address === getAddress(address)),
    recordedHalted: (chainId: string, address: string) =>
      halts.some((f) => f.chainId === chainId && f.address === getAddress(address)),
    haltsOfIdentity: (identity: string): HaltRecord[] =>
      halts
        .filter((f) => f.identity === identity)
        .map((f) => ({ chainId: f.chainId, address: f.address, seq: f.seq, reason: String(f.reason) })),
  };
}

/**
 * Every way the registry is malformed, or (given the recorded builds and designations) names a build or designation
 * that does not exist or does not match; empty: valid. With `null` for both, only the registry's own rules are
 * checked — what the binding gate needs to read it (registryShapeErrors); CI and the deployment tooling check all.
 */
export function registryErrors(
  doc: RegistryDoc,
  builds: readonly WrapperBuild[] | null,
  designations: readonly ProgramDesignation[] | null,
): string[] {
  const errors: string[] = [];
  if (doc?.schema !== REGISTRY_SCHEMA) errors.push(`the registry's schema must be ${REGISTRY_SCHEMA}`);
  if (!same(doc?.migratedFrom, MIGRATED_FROM)) errors.push("migratedFrom must record SP1-TD2's empty v1 registry");
  if (!Array.isArray(doc?.facts)) return [...errors, "the registry's facts must be a list"];
  const registered = new Map<string, RegistryFact>();
  const haltedIdentities = new Map<string, HaltRecord[]>();
  doc.facts.forEach((f, i) => {
    const at = `registry fact #${i + 1}`;
    if (f?.seq !== i + 1) errors.push(`${at}: seq must be ${i + 1} (facts are numbered in order, from 1)`);
    if (typeof f?.chainId !== "string" || !/^[1-9][0-9]*$/.test(f.chainId)) {
      errors.push(`${at}: the chain id must be a decimal string`);
      return;
    }
    if (!isChecksummed(f.address)) {
      errors.push(`${at}: the wrapper address must be a checksummed address`);
      return;
    }
    if (!isBlock(f.observedAt?.block) || !isWord(f.observedAt?.blockHash)) {
      errors.push(`${at}: observedAt needs the block and its hash`);
    }
    const key = `${f.chainId}:${f.address}`;
    if (f.kind === "WRAPPER_REGISTERED") {
      if (registered.has(key)) errors.push(`${at}: ${key} is already registered`);
      if (typeof f.wrapperBuild !== "string" || typeof f.designation !== "string") {
        errors.push(`${at}: a registration names its wrapper build and its designation`);
      }
      const build = builds === null ? undefined : builds.find((b) => b.id === f.wrapperBuild);
      if (builds !== null && !build) {
        errors.push(`${at}: wrapper build ${String(f.wrapperBuild)} is not a recorded build`);
      }
      const d = designations === null ? undefined : designations.find((x) => x.id === f.designation);
      if (designations !== null && !d) {
        errors.push(`${at}: designation ${String(f.designation)} is not a recorded designation`);
      }
      const code = f.sp1Verifier?.runtimeCodeKeccak;
      if (!isWord(code) || !isWord(f.programVKey)) {
        errors.push(`${at}: the SP1 verifier's runtime code hash and PROGRAM_VKEY must be 32-byte words`);
      } else if (f.identity !== identityOf(code as string, f.programVKey as string)) {
        errors.push(`${at}: its identity is not keccak256(abi.encode(SP1 verifier code hash, PROGRAM_VKEY))`);
      }
      if (d && (d.programVKey !== f.programVKey || d.identity !== f.identity)) {
        errors.push(`${at}: its vkey and identity are not designation ${d.id}'s`);
      }
      if (d && d.verifier.runtimeCodeKeccak !== code) {
        errors.push(`${at}: its SP1 verifier code is not designation ${d.id}'s verifier`);
      }
      if (build && build.pins.sp1VerifierCodehash !== code) {
        errors.push(`${at}: wrapper build ${build.id} pins another SP1 verifier`);
      }
      if (!isChecksummed(f.sp1Verifier?.address)) errors.push(`${at}: the SP1 verifier address must be checksummed`);
      if (!isChecksummed(f.haltPrincipal) || f.haltPrincipal === ZeroAddress) {
        errors.push(`${at}: the halt principal must be a non-zero checksummed address`);
      }
      if (!isWord(f.deployment?.txHash) || !isBlock(f.deployment?.block) || !isChecksummed(f.deployment?.deployer)) {
        errors.push(`${at}: the deployment needs its transaction, block and deployer`);
      } else if (isBlock(f.observedAt?.block) && Number(f.deployment?.block) > Number(f.observedAt?.block)) {
        errors.push(`${at}: observed before its deployment (block ${f.observedAt?.block} < ${f.deployment?.block})`);
      }
      const prior = haltedIdentities.get(f.identity);
      if (prior !== undefined && prior.length > 0) {
        errors.push(
          `${at}: identity ${f.identity} was halted (fact #${prior[0].seq} on chain ${prior[0].chainId}); ` +
            `a halted identity is never registered again, on any chain`,
        );
      }
      if (f.replaces !== null && f.replaces !== undefined) {
        if (!registered.has(`${f.chainId}:${String(f.replaces?.address)}`)) {
          errors.push(`${at}: replaces names no earlier registered wrapper on chain ${f.chainId}`);
        }
      }
      registered.set(key, f);
    } else if (f.kind === "WRAPPER_HALTED") {
      const registration = registered.get(key);
      if (!registration) {
        errors.push(`${at}: ${key} is not registered before its halt`);
        return;
      }
      if (f.identity !== registration.identity)
        errors.push(`${at}: the halted identity is not the registered wrapper's`);
      if (!(HALT_REASONS as readonly string[]).includes(String(f.reason))) {
        errors.push(`${at}: the halt reason must be one of ${HALT_REASONS.join(", ")}`);
      }
      if (!isWord(f.halt?.txHash) || !isBlock(f.halt?.block)) {
        errors.push(`${at}: the halt needs its transaction and block`);
      } else if ((f.halt as { block: number }).block < Number(registration.deployment?.block)) {
        errors.push(`${at}: the halt precedes the wrapper's deployment`);
      } else if (isBlock(f.observedAt?.block) && Number(f.halt?.block) > Number(f.observedAt?.block)) {
        errors.push(`${at}: observed before the halt (block ${f.observedAt?.block} < ${f.halt?.block})`);
      }
      const halts = haltedIdentities.get(registration.identity) ?? [];
      if (halts.some((h) => h.chainId === f.chainId && h.address === f.address)) {
        errors.push(`${at}: ${key} is recorded halted twice`);
      }
      halts.push({ chainId: f.chainId, address: f.address, seq: f.seq, reason: String(f.reason) });
      haltedIdentities.set(registration.identity, halts);
    } else {
      errors.push(`${at}: kind must be WRAPPER_REGISTERED or WRAPPER_HALTED`);
    }
  });
  return errors;
}

// ---------------------------------------------------------------------------------------------------------
// Append-only
// ---------------------------------------------------------------------------------------------------------

function isPrefix(older: unknown, newer: unknown): boolean {
  if (!Array.isArray(older) || !Array.isArray(newer) || older.length > newer.length) return false;
  return older.every((x, i) => same(x, newer[i]));
}

/** How a newer version of the registry fails to extend an older one (null: absent); empty when it is an append. */
export function registryExtensionErrors(older: string | null, newer: string | null): string[] {
  if (newer === null)
    return older === null ? [] : ["the registry was deleted; a published registry is never withdrawn"];
  let next: any;
  try {
    next = JSON.parse(newer);
  } catch {
    return ["the registry is not JSON"];
  }
  // Where the record first appears it is SP1-TD2's v1 list: a history that starts at the fact log (an orphan root, as
  // a rewrite would make) would skip the only migration the v1 list allows.
  if (older === null) {
    return next?.schema === REGISTRY_V1_SCHEMA
      ? []
      : [
          "the registry's first version must be a v1 registry (SP1-TD2's list): a history that starts at the fact log skips the only migration allowed",
        ];
  }
  let prev: any;
  try {
    prev = JSON.parse(older);
  } catch {
    return ["the earlier registry is not JSON, so no extension can be proved"];
  }
  if (prev?.schema === REGISTRY_V1_SCHEMA) {
    if (next?.schema === REGISTRY_V1_SCHEMA) {
      return isPrefix(prev.entries, next.entries) ? [] : ["it removed or rewrote a published v1 entry"];
    }
    if (next?.schema === REGISTRY_SCHEMA) {
      return Array.isArray(prev.entries) && prev.entries.length === 0 && same(next.migratedFrom, MIGRATED_FROM)
        ? []
        : ["it migrated a non-empty v1 registry: only SP1-TD2's empty list may become the fact log"];
    }
    return ["it changed the schema to an unknown one"];
  }
  if (prev?.schema === REGISTRY_SCHEMA) {
    if (next?.schema !== REGISTRY_SCHEMA) return ["it changed the schema away from the v2 fact log"];
    const errors: string[] = [];
    if (!same(prev.migratedFrom, next.migratedFrom)) errors.push("it rewrote migratedFrom");
    if (!isPrefix(prev.facts, next.facts)) {
      errors.push("it removed or rewrote a published fact (facts may only be appended)");
    }
    return errors;
  }
  return ["the earlier registry has an unknown schema, so no extension can be proved"];
}

// ---------------------------------------------------------------------------------------------------------
// The repository
// ---------------------------------------------------------------------------------------------------------

/** The committed registry (parsed; validate it with registryErrors). */
export function readRegistry(repoRoot = "."): RegistryDoc {
  return JSON.parse(readFileSync(resolve(repoRoot, REGISTRY_REL), "utf8")) as RegistryDoc;
}

/** The registry's content against the recorded builds and designations, and every published record's history. */
export function validateRegistryInRepo(repoRoot = "."): string[] {
  return [
    ...registryErrors(readRegistry(repoRoot), readWrapperBuilds(repoRoot), readDesignations(repoRoot)),
    ...fileHistoryErrors(repoRoot, REGISTRY_REL, registryExtensionErrors),
    ...directoryHistoryErrors(repoRoot, DESIGNATIONS_DIR),
    ...directoryHistoryErrors(repoRoot, DESIGNATION_EVIDENCE_DIR),
    ...directoryHistoryErrors(repoRoot, WRAPPER_BUILDS_DIR),
  ];
}
