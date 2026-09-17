/**
 * Operations guard for the Docker Compose runtime surfaces: no long-running service holds a deployment credential
 * (B1), and nothing publishes Hardhat JSON-RPC beyond the host's loopback interface by default (B2).
 *
 * B1. Deployment credentials belong to the one-shot deployment job. The persistent node serves Hardhat's in-memory
 *     chain 31337 and the dev container only keeps a shell alive for `docker compose exec`; neither reads one.
 *     hardhat.config.ts reads DEPLOYER_PRIVATE_KEY only as the account of the sepolia and base-sepolia HTTP networks
 *     and the RPC URLs only as their endpoints, scripts/deploy.ts alone reads PQC_VERIFIER_ADDRESS, and nothing reads
 *     ETHERSCAN_API_KEY. The RPC URLs count as credentials because docs/DIGITALOCEAN_DEPLOYMENT.md tells operators to
 *     swap in private endpoints, which embed an API key. So every service other than the deployment job:
 *     - declares no env_file: it injects every key of the file, which this guard cannot see;
 *     - names no deployment or secret-shaped variable anywhere (environment, command, labels, build args);
 *     - sets only environment variables that a process in it is documented to read;
 *     - mounts no env file, bind-mounts nothing into a node, and bind-mounts the project directory only with dotenv
 *       pointed away from the mounted .env (hardhat.config.ts imports dotenv/config, which reads <cwd>/.env);
 *     - uses no anchor, alias, merge key, extends, secrets or configs, which move injection out of the reader's sight.
 *     The deployment job keeps its credentials only while it stays what makes that acceptable: profile-gated (a plain
 *     `docker compose up` never deploys), one-shot (no restart policy) and publishing nothing — and only credentials a
 *     process in the image actually reads, so being the deployer does not entitle it to values nothing consumes.
 *     LIMIT: the Droplet deployer declares `env_file: .env`, which injects every key of the operator's own file. This
 *     guard governs what the compose files declare; it cannot see, and does not claim anything about, the contents of a
 *     file on the server. Removing a declaration stops Compose passing a value, not an operator from putting it back.
 *
 * B2. A port published without a host IP binds every host interface, and Docker writes its own iptables rules for it,
 *     ahead of host firewalls such as ufw, so a firewall is no substitute for the binding. Every port a base compose
 *     file publishes binds a loopback address; a service whose command starts no server publishes nothing; a node
 *     listens on 0.0.0.0 inside its container, which is what lets Docker forward the loopback port to it. Public
 *     exposure is an opt-in override file that Compose never loads implicitly, and documented `docker run`
 *     publications bind loopback as well.
 *
 * Roles come from what a service runs (its command:, or the Dockerfile CMD when it declares none), never from its
 * name, so a renamed service keeps its constraints. Pure static read of comment-stripped compose text, in the style of
 * test/RequiredStatusContextsWorkflow.test.ts: no YAML parser dependency, no Docker, no network. Shapes the reader
 * does not model fail closed instead of passing.
 *
 * Run:  npm test  (included in the default Hardhat test suite)
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

/** Every compose file in the repository root, and how an operator reaches it. A new compose file must be classified. */
const COMPOSE_FILES: Record<string, "base" | "opt-in override"> = {
  "docker-compose.droplet.yml": "base",
  "docker-compose.public-rpc.yml": "opt-in override",
  "docker-compose.yml": "base",
};

/** File names Compose reads without a -f flag; an opt-in override must never carry one. */
const IMPLICIT_COMPOSE_FILES = [
  "compose.yaml",
  "compose.yml",
  "docker-compose.yaml",
  "docker-compose.yml",
  "compose.override.yaml",
  "compose.override.yml",
  "docker-compose.override.yaml",
  "docker-compose.override.yml",
];

/** Variables that carry a credential for, or exist only to serve, a Sepolia deployment. */
const DEPLOYMENT_VARIABLES = [
  "DEPLOYER_PRIVATE_KEY",
  "ETHERSCAN_API_KEY",
  "PQC_VERIFIER_ADDRESS",
  "SEPOLIA_RPC_URL",
  "BASE_SEPOLIA_RPC_URL",
];

/** A variable name shaped like a credential, whatever its prefix. */
const SECRET_SHAPED = /\b[A-Z0-9_]*(?:PRIVATE_KEY|MNEMONIC|SECRET|PASSWORD|API_KEY|TOKEN)[A-Z0-9_]*\b/g;

/**
 * Dotenv file names that hold secrets as soon as an operator populates them. `.dockerignore` decides build-context
 * membership on its own, and the Dockerfile copies the whole context twice (`COPY . .` in builder and in runner), so a
 * variant left in the context lands in the published image, not only in a discarded build stage. Two Docker pattern
 * rules make the naive spelling insufficient: a pattern without a wildcard matches one literal name, so `.env` alone
 * leaves every sibling in; and a pattern carrying no double-star directory prefix is anchored at the context root, so it
 * never reaches a subdirectory. A nested variant was measured entering a real build context with a root-only rule.
 */
const SECRET_DOTENV_FILES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.production.local",
  ".env.development",
  ".env.development.local",
  ".env.test",
  ".env.sepolia",
  ".env.droplet",
  ".env.2026",
  ".env.a",
  ".envrc",
  "scripts/.env",
  "scripts/.env.local",
  "src/.env.production",
  "pqc/.envrc",
  "zkvm/host/.env.local",
];

/** The one dotenv file the repository ships on purpose: a public template, which every populated variant is copied from. */
const PUBLIC_DOTENV_TEMPLATE = ".env.example";

/**
 * Where a variable may acquire a consumer: production code that runs in the image. Compose files, documentation and this
 * guard are excluded on purpose — a name being passed to a container, described in a runbook or listed here is not a
 * process reading it, and letting any of them count would make the invariant satisfy itself.
 */
const CONSUMER_SOURCES = ["hardhat.config.ts", "pqc", "scripts", "src"];

/** The Droplet install directory, which marks a documented command as running on the server rather than a workstation. */
const DROPLET_DIRECTORY = "/opt/walletwall-vault";
/** The compose file the Droplet runs. Without `-f`, Compose loads docker-compose.yml, which builds from absent sources. */
const DROPLET_COMPOSE_FILE = "docker-compose.droplet.yml";

/**
 * The environment variables a long-running service may set, each with the process that reads it. Extending this list
 * needs the same justification: a documented runtime dependency, never "the deployment job has it too".
 */
const LONG_RUNNING_ENVIRONMENT: Record<string, string> = {
  DOTENV_CONFIG_PATH: "dotenv/config, imported by hardhat.config.ts, reads this path instead of <cwd>/.env",
};

const ROLES = ["deployment job", "JSON-RPC node", "keep-alive shell"];
const DEPLOYS = /deploy-entrypoint\.sh|\bnpm run deploy\b|\bhardhat run scripts\/deploy/;
const SERVES_JSON_RPC = /\bhardhat node\b/;
/** Commands that keep a container alive without starting any server. */
const KEEP_ALIVE = ["tail -f /dev/null", "sleep infinity"];

// ── Reader ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/** A line without its YAML comment: a `#` at the start or after whitespace, outside quotes. */
function stripComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote !== "") {
      if (c === quote) quote = "";
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === "#" && (i === 0 || line[i - 1] === " " || line[i - 1] === "\t")) {
      return line.slice(0, i).trimEnd();
    }
  }
  return line.trimEnd();
}

const indentOf = (line: string): number => line.length - line.trimStart().length;
const unquote = (text: string): string => text.trim().replace(/^(["'])(.*)\1$/, "$2");
const keyOf = (line: string): string => unquote(line.trim().split(":")[0]);
const isKey = (line: string, key: string): boolean =>
  line.trimStart() === `${key}:` || line.trimStart().startsWith(`${key}: `);
/** The inline value after `key:`, unquoted; "" when the value is a nested block. */
const valueOf = (line: string): string => unquote(line.slice(line.indexOf(":") + 1));

/** Lines nested under the key at `lines[at]`: everything indented deeper (blank lines included) up to the next sibling. */
function childrenOf(lines: string[], at: number): string[] {
  const children: string[] = [];
  for (let i = at + 1; i < lines.length && (lines[i].trim() === "" || indentOf(lines[i]) > indentOf(lines[at])); i++) {
    children.push(lines[i]);
  }
  return children;
}

/** Indices of the shallowest non-blank lines: the keys of the mapping that `lines` holds. */
function topKeys(lines: string[]): number[] {
  const depth = Math.min(...lines.filter((line) => line.trim() !== "").map(indentOf));
  return lines.flatMap((line, i) => (line.trim() !== "" && indentOf(line) === depth ? [i] : []));
}

/** The scalars of a list given inline (`[a, b]`) or as `- item` lines under `lines[at]`; null for any other form. */
function listAt(lines: string[], at: number): string[] | null {
  const inline = valueOf(lines[at]);
  if (inline === "") {
    const children = childrenOf(lines, at).filter((line) => line.trim() !== "");
    if (children.some((line) => !line.trim().startsWith("- "))) return null;
    return children.map((line) => unquote(line.trim().slice(2)));
  }
  if (inline.startsWith("[") && inline.endsWith("]")) {
    return inline
      .slice(1, -1)
      .split(",")
      .map(unquote)
      .filter((item) => item !== "");
  }
  return null;
}

/** Each `- ` entry under `lines[at]`: a scalar, or a flat mapping written as `- key: value` lines; null otherwise. */
function entriesAt(lines: string[], at: number): (string | Record<string, string>)[] | null {
  if (valueOf(lines[at]) !== "") return listAt(lines, at);
  const mappingLine = /^[\w-]+:(\s|$)/;
  const entries: (string | Record<string, string>)[] = [];
  for (const line of childrenOf(lines, at).filter((l) => l.trim() !== "")) {
    const text = line.trim();
    const last = entries[entries.length - 1];
    if (text.startsWith("- ")) {
      const item = text.slice(2);
      entries.push(mappingLine.test(item) ? { [keyOf(item)]: valueOf(item) } : unquote(item));
    } else if (typeof last === "object" && mappingLine.test(text)) {
      last[keyOf(text)] = valueOf(text);
    } else {
      return null;
    }
  }
  return entries;
}

interface Service {
  file: string;
  name: string;
  /** Comment-stripped lines nested under the service's key. */
  body: string[];
}

/** Top-level keys a compose file may carry; anything else (include:, for one) is not modeled. */
const TOP_LEVEL_KEYS = ["services", "volumes", "networks", "name", "secrets", "configs", "version"];

/** The services of a compose file, plus every shape in it that the reader does not model. */
function readServices(file: string, text: string): { services: Service[]; unmodeled: string[] } {
  const lines = text
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .map(stripComment);
  const unmodeled: string[] = [];
  if (lines.some((line) => /^(---|\.\.\.)\s*$/.test(line))) unmodeled.push(`${file}: multi-document YAML`);
  const top = topKeys(lines);
  for (const at of top) {
    const key = keyOf(lines[at]);
    if (!TOP_LEVEL_KEYS.includes(key) && !key.startsWith("x-")) unmodeled.push(`${file}: top-level ${key}:`);
  }
  const root = top.find((at) => isKey(lines[at], "services"));
  if (root === undefined || valueOf(lines[root]) !== "") {
    unmodeled.push(`${file}: no block-style services:`);
    return { services: [], unmodeled };
  }
  const block = childrenOf(lines, root);
  const services: Service[] = [];
  for (const at of topKeys(block)) {
    const service = { file, name: keyOf(block[at]), body: childrenOf(block, at) };
    services.push(service);
    if (valueOf(block[at]) !== "") unmodeled.push(`${file} service ${service.name}: inline value`);
    const seen = new Set<string>();
    for (const index of topKeys(service.body)) {
      const line = service.body[index];
      // A quoted key, a key with a space before its colon, a merge key, or a sequence written at its key's indentation
      // would otherwise hide a key from keyAt below.
      if (!/^\s*[a-z_]+:( |$)/.test(line)) unmodeled.push(`${file} service ${service.name}: "${line.trim()}"`);
      else if (seen.has(keyOf(line))) unmodeled.push(`${file} service ${service.name}: duplicate ${keyOf(line)}:`);
      seen.add(keyOf(line));
    }
  }
  return { services, unmodeled };
}

/** Index in `service.body` of the service's own `key:` line. */
const keyAt = (service: Service, key: string): number | undefined =>
  topKeys(service.body).find((at) => isKey(service.body[at], key));

/** The variables the service's environment: sets (null value: passed through from the host); null if not modeled. */
function environmentOf(service: Service): Map<string, string | null> | null {
  const variables = new Map<string, string | null>();
  const at = keyAt(service, "environment");
  if (at === undefined) return variables;
  const children = childrenOf(service.body, at).filter((line) => line.trim() !== "");
  if (valueOf(service.body[at]).startsWith("[") || children.some((line) => line.trim().startsWith("- "))) {
    const items = listAt(service.body, at);
    if (items === null) return null;
    for (const item of items) {
      const eq = item.indexOf("=");
      variables.set(eq < 0 ? item : item.slice(0, eq), eq < 0 ? null : item.slice(eq + 1));
    }
    return variables;
  }
  if (valueOf(service.body[at]) !== "") return null;
  const depth = Math.min(...children.map(indentOf));
  for (const line of children) {
    if (indentOf(line) !== depth) return null;
    variables.set(keyOf(line), valueOf(line) === "" ? null : valueOf(line));
  }
  return variables;
}

/** Whether the service runs this repository's image, whose default command is the Dockerfile CMD. */
function usesRepositoryImage(service: Service): boolean {
  const imageAt = keyAt(service, "image");
  if (keyAt(service, "build") !== undefined) return true;
  return imageAt !== undefined && valueOf(service.body[imageAt]).includes("walletwall-vault");
}

/** What the service runs: its command: (scalar or list), else the Dockerfile CMD for this repository's image. */
function commandOf(service: Service, dockerfileCmd: string | null): string | null {
  const at = keyAt(service, "command");
  if (at === undefined) return usesRepositoryImage(service) ? dockerfileCmd : null;
  const inline = valueOf(service.body[at]);
  if (inline !== "" && !inline.startsWith("[")) return inline;
  return listAt(service.body, at)?.join(" ") ?? null;
}

/** The service's role, derived from what it runs; any string outside ROLES says why no role applies. */
function roleOf(service: Service, dockerfileCmd: string | null): string {
  if (keyAt(service, "entrypoint") !== undefined) return "entrypoint: replaces what the image runs (not modeled)";
  const command = commandOf(service, dockerfileCmd);
  if (command === null) return "no command: and no known default command (not modeled)";
  const deploys = DEPLOYS.test(command);
  const serves = SERVES_JSON_RPC.test(command);
  if (deploys && serves) return "a command that both deploys and serves JSON-RPC (not modeled)";
  if (deploys) return "deployment job";
  if (serves) return "JSON-RPC node";
  if (KEEP_ALIVE.includes(command.trim())) return "keep-alive shell";
  return `command "${command}" (not modeled)`;
}

interface Mount {
  source: string | null;
  target: string;
  /** A host path, rather than a named or anonymous volume. */
  bind: boolean;
}

const isHostPath = (source: string): boolean => /^[.~/$]/.test(source) || /^[A-Za-z]:[\\/]/.test(source);

/** The service's volumes:, in short (`source:target[:mode]`) or long syntax; null when a form is not modeled. */
function mountsOf(service: Service): Mount[] | null {
  const at = keyAt(service, "volumes");
  if (at === undefined) return [];
  const entries = entriesAt(service.body, at);
  if (entries === null) return null;
  const mounts: Mount[] = [];
  for (const entry of entries) {
    if (typeof entry !== "string") {
      if (!entry.target) return null;
      const source = entry.source ?? null;
      mounts.push({
        source,
        target: entry.target,
        bind: entry.type === "bind" || (source !== null && isHostPath(source)),
      });
      continue;
    }
    const parts = entry.split(":");
    if (/^[A-Za-z]$/.test(parts[0]) && /^[\\/]/.test(parts[1] ?? "")) parts.splice(0, 2, `${parts[0]}:${parts[1]}`);
    if (parts.length === 1) mounts.push({ source: null, target: parts[0], bind: false });
    else if (parts.length <= 3) mounts.push({ source: parts[0], target: parts[1], bind: isHostPath(parts[0]) });
    else return null;
  }
  return mounts;
}

interface Publication {
  spec: string;
  /** The host address the port binds; null when none is given, which binds every host interface. */
  hostIp: string | null;
}

/** One short-syntax port, `[host_ip:][published:]target[/protocol]`; null when the form is not modeled. */
function parsePort(spec: string): Publication | null {
  if (spec.includes("$")) return null;
  let rest = spec.replace(/\/(tcp|udp|sctp)$/, "");
  let hostIp: string | null = null;
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]:");
    if (close < 0) return null;
    hostIp = rest.slice(1, close);
    rest = rest.slice(close + 2);
  }
  const parts = rest.split(":");
  if (hostIp === null && parts.length === 3) hostIp = parts.shift() as string;
  const port = /^[0-9]+(-[0-9]+)?$/;
  const target = parts[parts.length - 1];
  const published = parts.length === 2 ? parts[0] : "";
  if (parts.length > 2 || !port.test(target) || (published !== "" && !port.test(published))) return null;
  if (hostIp !== null && !/^[0-9]+(\.[0-9]+){3}$/.test(hostIp) && !hostIp.includes(":")) return null;
  return { spec, hostIp };
}

/** The service's ports:, in short or long syntax; null when a form is not modeled. */
function publicationsOf(service: Service): Publication[] | null {
  const at = keyAt(service, "ports");
  if (at === undefined) return [];
  const entries = entriesAt(service.body, at);
  if (entries === null) return null;
  const publications: Publication[] = [];
  for (const entry of entries) {
    if (typeof entry === "string") {
      const publication = parsePort(entry);
      if (publication === null) return null;
      publications.push(publication);
    } else {
      if (!entry.target || Object.values(entry).some((value) => value.includes("$"))) return null;
      const hostIp = entry.host_ip ? entry.host_ip.replace(/^\[(.*)\]$/, "$1") : null;
      publications.push({ spec: `target ${entry.target}`, hostIp });
    }
  }
  return publications;
}

const isLoopback = (ip: string): boolean => /^127(\.[0-9]+){3}$/.test(ip) || ip === "::1";

// ── Invariants ──────────────────────────────────────────────────────────────────────────────────────────────────────

/** Why a deployment job may not hold deployment credentials; empty when it is profile-gated, one-shot and unpublished. */
function deploymentJobGaps(service: Service): string[] {
  const gaps: string[] = [];
  const profilesAt = keyAt(service, "profiles");
  if (profilesAt === undefined || (listAt(service.body, profilesAt) ?? []).length === 0) {
    gaps.push("no profiles:, so a plain `docker compose up` runs the deployment");
  }
  const restartAt = keyAt(service, "restart");
  if (restartAt !== undefined && valueOf(service.body[restartAt]) !== "no") {
    gaps.push(`restart: ${valueOf(service.body[restartAt])} runs the deployment again`);
  }
  if (keyAt(service, "ports") !== undefined) gaps.push("ports: on a deployment job");
  return gaps;
}

/**
 * Credentials a deployment job declares that nothing in the image reads. Being profile-gated earns the job the
 * credentials its deployment needs, not every value that once lived in the deployment environment: an unread secret is
 * reachable from the container and from `docker inspect` while buying no capability. Re-admitting one is deliberate —
 * add its reader, and this returns empty again.
 */
function unconsumedCredentials(service: Service, sources: string[] = CONSUMER_SOURCES): string[] {
  const environment = environmentOf(service);
  if (environment === null) return ["environment: in a form the reader does not model"];
  const text = service.body.join("\n");
  const declared = new Set([
    ...environment.keys(),
    ...DEPLOYMENT_VARIABLES.filter((name) => new RegExp(`\\b${name}\\b`).test(text)),
    ...(text.match(SECRET_SHAPED) ?? []),
  ]);
  return [...declared]
    .filter((name) => DEPLOYMENT_VARIABLES.includes(name) || new RegExp(SECRET_SHAPED.source).test(name))
    .filter((name) => consumersOf(name, sources).length === 0)
    .sort()
    .map((name) => `receives ${name}, which no file under ${sources.join(", ")} reads`);
}

/** Why a long-running service might hold a deployment credential or load a .env; empty when nothing can. */
function credentialFindings(service: Service, role: string): string[] {
  const findings: string[] = [];
  const text = service.body.join("\n");
  for (const key of ["env_file", "secrets", "configs", "extends"]) {
    if (keyAt(service, key) !== undefined) findings.push(`${key}: brings in values this guard cannot see`);
  }
  if (/^\s*(- )?<<\s*:/m.test(text) || /(:|-)\s+[&*][\w-]+/.test(text)) {
    findings.push("an anchor, alias or merge key brings in values this guard cannot see");
  }
  const named = new Set([
    ...DEPLOYMENT_VARIABLES.filter((name) => new RegExp(`\\b${name}\\b`).test(text)),
    ...(text.match(SECRET_SHAPED) ?? []),
  ]);
  for (const name of [...named].sort()) findings.push(`names ${name}`);
  const environment = environmentOf(service);
  if (environment === null) findings.push("environment: in a form the reader does not model");
  for (const name of environment?.keys() ?? []) {
    if (!Object.hasOwn(LONG_RUNNING_ENVIRONMENT, name)) {
      findings.push(`sets ${name}, which no process in it is documented to read`);
    }
  }
  const mounts = mountsOf(service);
  if (mounts === null) findings.push("volumes: in a form the reader does not model");
  for (const mount of mounts ?? []) {
    if (!mount.bind || mount.source === null) continue;
    if ((mount.source.split(/[\\/]/).pop() ?? "").startsWith(".env")) {
      findings.push(`mounts ${mount.source}, an env file`);
    } else if (role === "JSON-RPC node") {
      findings.push(`bind-mounts ${mount.source} into a network-facing node`);
    } else if ([".", "./", "$PWD", "${PWD}"].includes(mount.source)) {
      const path = environment?.get("DOTENV_CONFIG_PATH") ?? null;
      const outside =
        path !== null && path.startsWith("/") && path !== mount.target && !path.startsWith(`${mount.target}/`);
      if (!outside) {
        findings.push(
          `bind-mounts the project directory at ${mount.target}, whose .env dotenv/config loads unless ` +
            "DOTENV_CONFIG_PATH points outside the mount",
        );
      }
    } else {
      findings.push(`bind-mounts ${mount.source} (not modeled)`);
    }
  }
  return findings;
}

/** Why the service might be reachable beyond the host loopback interface; empty when it cannot. */
function exposureFindings(service: Service, role: string): string[] {
  const findings: string[] = [];
  const networkModeAt = keyAt(service, "network_mode");
  if (networkModeAt !== undefined && valueOf(service.body[networkModeAt]) === "host") {
    findings.push("network_mode: host puts every listener on the host's own interfaces");
  }
  const publications = publicationsOf(service);
  if (publications === null) return [...findings, "ports: in a form the reader does not model"];
  for (const { spec, hostIp } of publications) {
    if (hostIp === null || hostIp === "0.0.0.0" || hostIp === "::") {
      findings.push(`publishes ${spec} on every host interface`);
    } else if (!isLoopback(hostIp)) {
      findings.push(`publishes ${spec} on ${hostIp}, which is not a loopback address`);
    }
  }
  if (role === "keep-alive shell" && publications.length > 0) {
    findings.push("publishes a port although its command starts no server");
  }
  return findings;
}

/** The final image's default command: the last CMD of the Dockerfile, in exec (JSON array) form; null otherwise. */
function dockerfileCommand(text: string): string | null {
  const cmd = text
    .split(/\r?\n/)
    .filter((line) => /^CMD\s/.test(line))
    .pop();
  if (cmd === undefined) return null;
  try {
    const argv: unknown = JSON.parse(cmd.slice(3).trim());
    return Array.isArray(argv) && argv.every((arg) => typeof arg === "string") ? argv.join(" ") : null;
  } catch {
    return null;
  }
}

/** Whether .dockerignore leaves `path` out of the build context: the last matching pattern decides, `!` re-includes. */
function dockerignoreExcludes(text: string, path: string): boolean {
  let excluded = false;
  for (const raw of text.split(/\r?\n/).map((line) => line.trim())) {
    if (raw === "" || raw.startsWith("#")) continue;
    const negated = raw.startsWith("!");
    const pattern = (negated ? raw.slice(1) : raw).replace(/^\/+|\/+$/g, "");
    const source = pattern
      .split("**/")
      .map((segment) =>
        segment
          .split("**")
          .map((part) =>
            part
              .replace(/[.+^${}()|[\]\\]/g, "\\$&")
              .replace(/\*/g, "[^/]*")
              .replace(/\?/g, "[^/]"),
          )
          .join(".*"),
      )
      .join("(?:.*/)?");
    if (new RegExp(`^${source}(/.*)?$`).test(path)) excluded = !negated;
  }
  return excluded;
}

/** Every `-p`/`--publish` value, and any `-P`/`--publish-all`, of a documented `docker run` command. */
function documentedPublications(file: string, text: string): { where: string; spec: string }[] {
  const lines = text.split(/\r?\n/);
  const found: { where: string; spec: string }[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/\bdocker run\b/.test(lines[i])) continue;
    let command = lines[i];
    for (let j = i; /\\\s*$/.test(lines[j]) && j + 1 < lines.length; j++) {
      command = `${command.replace(/\\\s*$/, " ")}${lines[j + 1]}`;
    }
    for (const match of command.matchAll(/(?:^|\s)(?:-p|--publish)(?:=|\s+)("[^"]*"|'[^']*'|\S+)/g)) {
      found.push({ where: `${file}:${i + 1}`, spec: unquote(match[1]) });
    }
    if (/(?:^|\s)(?:-P|--publish-all)(?=\s|$)/.test(command)) found.push({ where: `${file}:${i + 1}`, spec: "-P" });
  }
  return found;
}

/** Markdown files under `dir`, as repository-relative paths. */
function markdownUnder(dir: string): string[] {
  return readdirSync(resolve(dir), { withFileTypes: true }).flatMap((entry) => {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) return markdownUnder(path);
    return entry.name.endsWith(".md") ? [path] : [];
  });
}

/** Files under `dir` (or the file `dir` itself), as repository-relative paths. */
function filesUnder(dir: string): string[] {
  if (!existsSync(resolve(dir))) return [];
  const entries = (() => {
    try {
      return readdirSync(resolve(dir), { withFileTypes: true });
    } catch {
      return null;
    }
  })();
  if (entries === null) return [dir];
  return entries.flatMap((entry) => filesUnder(`${dir}/${entry.name}`));
}

/**
 * Whether `text`, a file at `path`, reads the environment variable `name`. A read is an explicit one: `process.env.NAME`,
 * `process.env["NAME"]`, or Hardhat's `configVariable("NAME")`. A shell expansion counts only in a `.sh` file, where
 * `${NAME}` can mean nothing else — in TypeScript it would also match a template literal holding a same-named local.
 */
function readsVariable(path: string, text: string, name: string): boolean {
  const patterns = [
    new RegExp(`process\\.env\\.${name}\\b`),
    new RegExp(`process\\.env\\[\\s*["']${name}["']\\s*\\]`),
    new RegExp(`configVariable\\(\\s*["']${name}["']\\s*\\)`),
  ];
  if (path.endsWith(".sh")) patterns.push(new RegExp(`\\$\\{${name}\\b[^}]*\\}`), new RegExp(`\\$${name}\\b`));
  return patterns.some((pattern) => pattern.test(text));
}

/** The production files that read `name`, as repository-relative paths. */
function consumersOf(name: string, sources: string[] = CONSUMER_SOURCES): string[] {
  return sources
    .flatMap((source) => filesUnder(source))
    .filter((path) => {
      try {
        return readsVariable(path, readFileSync(resolve(path), "utf8"), name);
      } catch {
        return false;
      }
    })
    .sort();
}

/** Fenced code blocks of a markdown file: the lines between a pair of ``` fences, each with its 1-based file line. */
function fencedBlocks(text: string): { line: number; text: string }[][] {
  const blocks: { line: number; text: string }[][] = [];
  let open: { line: number; text: string }[] | null = null;
  text.split(/\r?\n/).forEach((line, i) => {
    if (/^\s*```/.test(line)) {
      if (open === null) open = [];
      else {
        blocks.push(open);
        open = null;
      }
    } else if (open !== null) {
      open.push({ line: i + 1, text: line });
    }
  });
  return blocks;
}

/** Every `docker compose` invocation of a fenced block, joined across backslash-continued lines. */
function composeCommands(block: { line: number; text: string }[]): { line: number; command: string }[] {
  const found: { line: number; command: string }[] = [];
  for (let i = 0; i < block.length; i++) {
    if (!/\bdocker compose\b/.test(block[i].text)) continue;
    let command = block[i].text;
    for (let j = i; j + 1 < block.length && /\\\s*$/.test(block[j].text); j++) {
      command = `${command.replace(/\\\s*$/, " ")}${block[j + 1].text}`;
    }
    found.push({ line: block[i].line, command: command.trim().replace(/\s+/g, " ") });
  }
  return found;
}

describe("Compose guard — deployment credentials stay in the deployment job, JSON-RPC stays on loopback", function () {
  const dockerfileCmd = dockerfileCommand(readFileSync(resolve("Dockerfile"), "utf8"));
  const discovered = readdirSync(resolve("."))
    .filter((name) => /^(docker-)?compose(\.[\w-]+)*\.ya?ml$/.test(name))
    .sort();
  const unmodeled: string[] = [];
  const services = Object.entries(COMPOSE_FILES)
    .filter(([file, kind]) => kind === "base" && existsSync(resolve(file)))
    .flatMap(([file]) => {
      const read = readServices(file, readFileSync(resolve(file), "utf8"));
      unmodeled.push(...read.unmodeled);
      return read.services;
    });

  it("classifies every compose file in the repository root, and every classified file exists", function () {
    expect(discovered).to.deep.equal(Object.keys(COMPOSE_FILES).sort());
  });

  it("reads every base compose file and derives a role for every service (unmodeled shapes fail closed)", function () {
    expect(services, "no services read from the base compose files").to.not.be.empty;
    const roleless = services
      .filter((service) => !ROLES.includes(roleOf(service, dockerfileCmd)))
      .map((service) => `${service.file} service ${service.name}: ${roleOf(service, dockerfileCmd)}`);
    expect([...unmodeled, ...roleless]).to.deep.equal([]);
  });

  for (const service of services) {
    const role = roleOf(service, dockerfileCmd);
    describe(`${service.file} service ${service.name} (${role})`, function () {
      if (role === "deployment job") {
        it("stays a profile-gated one-shot job, the only kind of service that may hold deployment credentials", function () {
          expect(deploymentJobGaps(service)).to.deep.equal([]);
        });

        it("receives only credentials a process in the image actually reads (B1)", function () {
          expect(unconsumedCredentials(service)).to.deep.equal([]);
        });
        return;
      }

      it("holds no deployment credential and loads no .env (B1)", function () {
        expect(credentialFindings(service, role)).to.deep.equal([]);
      });

      it("publishes nothing beyond the host loopback interface (B2)", function () {
        expect(exposureFindings(service, role)).to.deep.equal([]);
      });

      if (role === "JSON-RPC node") {
        it("listens on the container interface, so Docker can forward the loopback port to it", function () {
          expect(commandOf(service, dockerfileCmd)).to.match(/--hostname[ =]0\.0\.0\.0\b/);
        });
      }
    });
  }

  describe("public JSON-RPC is an explicit opt-in", function () {
    const overrides = Object.entries(COMPOSE_FILES)
      .filter(([, kind]) => kind === "opt-in override")
      .map(([file]) => file);

    it("no override is read implicitly: none has a name Compose loads by default, and .env.example sets no COMPOSE_FILE", function () {
      expect(overrides, "no opt-in override is classified").to.not.be.empty;
      expect(overrides.filter((file) => IMPLICIT_COMPOSE_FILES.includes(file))).to.deep.equal([]);
      const template = readFileSync(resolve(".env.example"), "utf8").split(/\r?\n/);
      expect(template.filter((line) => /^\s*(export\s+)?COMPOSE_FILE\s*=/.test(line))).to.deep.equal([]);
    });

    for (const file of overrides) {
      it(`${file} replaces the port bindings of base services and changes nothing else`, function () {
        expect(existsSync(resolve(file)), `${file} does not exist`).to.equal(true);
        const read = readServices(file, readFileSync(resolve(file), "utf8"));
        expect(read.unmodeled).to.deep.equal([]);
        expect(read.services, `${file} overrides no service`).to.not.be.empty;
        for (const service of read.services) {
          const where = `${file} service ${service.name}`;
          expect(
            services.map((base) => base.name),
            where,
          ).to.include(service.name);
          expect(
            topKeys(service.body).map((at) => keyOf(service.body[at])),
            where,
          ).to.deep.equal(["ports"]);
          // Compose appends a ports: list to the base file's; only the !override tag replaces the loopback binding.
          expect(valueOf(service.body[keyAt(service, "ports") as number]), where).to.equal("!override");
        }
      });
    }
  });

  describe(".dockerignore keeps dotenv secrets out of the build context, and so out of the image (B1)", function () {
    const dockerignore = readFileSync(resolve(".dockerignore"), "utf8");

    it("excludes every secret-bearing dotenv variant, not only the bare .env", function () {
      const admitted = SECRET_DOTENV_FILES.filter((name) => !dockerignoreExcludes(dockerignore, name));
      expect(admitted, "these dotenv files can still enter the build context").to.deep.equal([]);
    });

    it("excludes an arbitrary .env suffix, at the root and in a subdirectory, so the rule generalizes", function () {
      // A drawn suffix, not a listed one: a rule that enumerates the names known today cannot satisfy this.
      const suffix = Math.random().toString(36).slice(2, 10);
      for (const name of [`.env.${suffix}`, `scripts/.env.${suffix}`, `a/b/c/.env.${suffix}`]) {
        expect(dockerignoreExcludes(dockerignore, name), `${name} can enter the build context`).to.equal(true);
      }
    });

    it(`keeps ${PUBLIC_DOTENV_TEMPLATE} in the context, and that template carries no populated secret`, function () {
      // Positive control: the exclusion must be a dotenv-secret rule, not a blanket sweep that also drops the template
      // the repository ships and documents (`cp .env.example .env`). The exception holds only while the template stays
      // a template: a secret-shaped name in it must have no value.
      expect(dockerignoreExcludes(dockerignore, PUBLIC_DOTENV_TEMPLATE)).to.equal(false);
      const populated = readFileSync(resolve(PUBLIC_DOTENV_TEMPLATE), "utf8")
        .split(/\r?\n/)
        .filter((line) => !line.trimStart().startsWith("#"))
        .flatMap((line) => {
          const [name, ...rest] = line.split("=");
          return new RegExp(SECRET_SHAPED.source).test(name.trim()) && rest.join("=").trim() !== ""
            ? [`${name.trim()} has a value`]
            : [];
        });
      expect(populated, `${PUBLIC_DOTENV_TEMPLATE} may only hold empty or public values`).to.deep.equal([]);
    });
  });

  it("every documented Droplet compose command names the Droplet compose file", function () {
    // Compose loads docker-compose.yml when no -f is given. On the Droplet that file is the wrong one: its vault-deploy
    // builds from a source tree the server does not have, and it carries no env_file, so the Droplet's populated .env is
    // never read. A block that names the Droplet install directory is a command run on the server, and must pass -f.
    expect(Object.keys(COMPOSE_FILES)).to.include(DROPLET_COMPOSE_FILE);
    const docs = ["README.md", ...markdownUnder("docs")];
    const onDroplet = docs.flatMap((file) =>
      fencedBlocks(readFileSync(resolve(file), "utf8"))
        .filter((block) => block.some(({ text }) => text.includes(DROPLET_DIRECTORY)))
        .flatMap((block) => composeCommands(block).map(({ line, command }) => ({ where: `${file}:${line}`, command }))),
    );
    expect(onDroplet, "no documented command runs compose on the Droplet; the scan saw nothing").to.not.be.empty;
    const missing = onDroplet
      .filter(({ command }) => !command.includes(DROPLET_COMPOSE_FILE))
      .map(({ where, command }) => `${where}: ${command}`);
    expect(missing, `these run on the Droplet without -f ${DROPLET_COMPOSE_FILE}`).to.deep.equal([]);
  });

  it("every documented `docker run` port publication binds the host loopback interface (B2)", function () {
    const docs = ["README.md", ...markdownUnder("docs")];
    expect(docs).to.include("docs/DIGITALOCEAN_DEPLOYMENT.md");
    const documented = docs.flatMap((file) => documentedPublications(file, readFileSync(resolve(file), "utf8")));
    expect(documented, "no documented docker run publishes a port; the scan saw nothing").to.not.be.empty;
    const unsafe = documented
      .filter(({ spec }) => {
        const publication = parsePort(spec);
        return publication === null || publication.hostIp === null || !isLoopback(publication.hostIp);
      })
      .map(({ where, spec }) => `${where}: ${spec}`);
    expect(unsafe).to.deep.equal([]);
  });

  describe("reader self-check on synthetic compose files (a parsing regression must not pass silently)", function () {
    const NODE = "npx hardhat node --hostname 0.0.0.0";
    /** The single service `svc` of a synthetic compose file whose shapes the reader models. */
    const service = (...lines: string[]): Service => {
      const read = readServices("synthetic.yml", ["services:", "  svc:", ...lines].join("\n"));
      expect(read.unmodeled).to.deep.equal([]);
      return read.services[0];
    };
    const node = (...lines: string[]) =>
      service("    image: walletwall-vault:latest", `    command: ${NODE}`, ...lines);
    const shell = (...lines: string[]) =>
      service("    image: walletwall-vault:local", "    command: tail -f /dev/null", ...lines);
    const job = (...lines: string[]) =>
      service("    image: walletwall-vault:latest", "    command: /bin/sh /app/scripts/deploy-entrypoint.sh", ...lines);

    it("derives a role from what a service runs, including the Dockerfile CMD, and never from its name", function () {
      expect(roleOf(node(), null)).to.equal("JSON-RPC node");
      expect(roleOf(shell(), null)).to.equal("keep-alive shell");
      expect(roleOf(job(), null)).to.equal("deployment job");
      expect(roleOf(service("    image: walletwall-vault:latest"), NODE)).to.equal("JSON-RPC node");
      expect(ROLES).to.not.include(roleOf(service("    image: postgres:16"), NODE));
      const renamed = readServices(
        "synthetic.yml",
        ["services:", "  vault-deploy:", "    image: walletwall-vault:latest", `    command: ${NODE}`].join("\n"),
      ).services[0];
      expect(roleOf(renamed, null)).to.equal("JSON-RPC node");
    });

    it("finds env_file on a node in scalar, commented, list and long form", function () {
      for (const shape of [
        ["    env_file: .env"],
        ["    env_file: .env                   # /opt/walletwall-vault/.env on the Droplet"],
        ["    env_file:", "      - .env"],
        ["    env_file:", "      - path: ./.env", "        required: false"],
      ]) {
        expect(credentialFindings(node(...shape), "JSON-RPC node"), shape.join(" ")).to.deep.equal([
          "env_file: brings in values this guard cannot see",
        ]);
      }
    });

    it("finds a deployment variable in list, map, flow, label and command-interpolation shapes", function () {
      const shapes: [string[], string][] = [
        [["    environment:", "      - DEPLOYER_PRIVATE_KEY=${DEPLOYER_PRIVATE_KEY:-}"], "DEPLOYER_PRIVATE_KEY"],
        [["    environment:", "      ETHERSCAN_API_KEY: placeholder"], "ETHERSCAN_API_KEY"],
        [["    environment: [SEPOLIA_RPC_URL]"], "SEPOLIA_RPC_URL"],
        [["    labels:", '      - "rpc=${BASE_SEPOLIA_RPC_URL}"'], "BASE_SEPOLIA_RPC_URL"],
      ];
      for (const [lines, name] of shapes) {
        expect(credentialFindings(node(...lines), "JSON-RPC node"), lines.join(" ")).to.include(`names ${name}`);
      }
      const smuggled = service(
        "    image: walletwall-vault:latest",
        `    command: sh -c "export VERIFIER=$PQC_VERIFIER_ADDRESS; ${NODE}"`,
      );
      expect(roleOf(smuggled, null)).to.equal("JSON-RPC node");
      expect(credentialFindings(smuggled, "JSON-RPC node")).to.deep.equal(["names PQC_VERIFIER_ADDRESS"]);
    });

    it("allows a deployer key only on a profile-gated, one-shot, unpublished deployment job", function () {
      const credentialed = [
        "    env_file: .env",
        "    environment:",
        "      - DEPLOYER_PRIVATE_KEY=${DEPLOYER_PRIVATE_KEY}",
      ];
      expect(deploymentJobGaps(job("    profiles: [deploy]", ...credentialed))).to.deep.equal([]);
      expect(deploymentJobGaps(job(...credentialed))).to.have.lengthOf(1);
      expect(
        deploymentJobGaps(job("    profiles: [deploy]", "    restart: unless-stopped", ...credentialed)),
      ).to.have.lengthOf(1);
      expect(
        deploymentJobGaps(job("    profiles: [deploy]", "    ports:", '      - "127.0.0.1:8545:8545"')),
      ).to.have.lengthOf(1);
      expect(credentialFindings(node(...credentialed), "JSON-RPC node")).to.not.be.empty;
    });

    it("reads a missing or wildcard host IP, and a random host port, as every interface, and loopback forms as safe", function () {
      const exposure = (...ports: string[]) => exposureFindings(node("    ports:", ...ports), "JSON-RPC node");
      for (const unsafe of [
        ['      - "8545:8545"'],
        ["      - 8545:8545"],
        ['      - "0.0.0.0:8545:8545"'],
        ['      - "[::]:8545:8545"'],
        ['      - "8545"'],
        ["      - target: 8545", '        published: "8545"'],
      ]) {
        expect(exposure(...unsafe), unsafe.join(" ")).to.have.lengthOf(1);
      }
      expect(exposureFindings(node('    ports: ["8545:8545"]'), "JSON-RPC node")).to.have.lengthOf(1);
      for (const safe of [
        ['      - "127.0.0.1:8545:8545"'],
        ["      - 127.0.0.1:8545:8545"],
        ['      - "[::1]:8545:8545"'],
        ['      - "127.0.0.1::8545"'],
        ["      - target: 8545", "        host_ip: 127.0.0.1", '        published: "8545"'],
      ]) {
        expect(exposure(...safe), safe.join(" ")).to.deep.equal([]);
      }
    });

    it("fails closed on network_mode: host, an interpolated host IP, and a non-loopback address", function () {
      expect(exposureFindings(node("    network_mode: host"), "JSON-RPC node")).to.have.lengthOf(1);
      expect(
        exposureFindings(node("    ports:", '      - "${RPC_BIND:-127.0.0.1}:8545:8545"'), "JSON-RPC node"),
      ).to.deep.equal(["ports: in a form the reader does not model"]);
      expect(exposureFindings(node("    ports:", '      - "10.0.0.5:8545:8545"'), "JSON-RPC node")).to.have.lengthOf(1);
    });

    it("passes a keep-alive shell that publishes nothing, and fails one that publishes a port", function () {
      expect(credentialFindings(shell(), "keep-alive shell")).to.deep.equal([]);
      expect(exposureFindings(shell(), "keep-alive shell")).to.deep.equal([]);
      expect(exposureFindings(shell("    ports:", '      - "127.0.0.1:8545:8545"'), "keep-alive shell")).to.deep.equal([
        "publishes a port although its command starts no server",
      ]);
    });

    it("needs DOTENV_CONFIG_PATH outside a project bind mount, and refuses env-file mounts and binds into a node", function () {
      const mounted = ["    volumes:", "      - .:/app", "      - vault_cache:/app/cache"];
      const redirected = (path: string) => shell(...mounted, "    environment:", `      - DOTENV_CONFIG_PATH=${path}`);
      expect(credentialFindings(shell(...mounted), "keep-alive shell")).to.have.lengthOf(1);
      expect(credentialFindings(redirected("/dev/null"), "keep-alive shell")).to.deep.equal([]);
      expect(credentialFindings(redirected("/app/.env"), "keep-alive shell")).to.have.lengthOf(1);
      expect(credentialFindings(redirected(".env"), "keep-alive shell")).to.have.lengthOf(1);
      expect(
        credentialFindings(
          shell(...mounted, "    environment:", "      DOTENV_CONFIG_PATH: /dev/null"),
          "keep-alive shell",
        ),
      ).to.deep.equal([]);
      expect(credentialFindings(node("    volumes:", "      - ./.env:/app/.env:ro"), "JSON-RPC node")).to.deep.equal([
        "mounts ./.env, an env file",
      ]);
      expect(
        credentialFindings(node("    volumes:", "      - /opt/walletwall-vault:/app"), "JSON-RPC node"),
      ).to.deep.equal(["bind-mounts /opt/walletwall-vault into a network-facing node"]);
      expect(
        credentialFindings(
          node("    volumes:", "      - type: bind", "        source: .", "        target: /app"),
          "JSON-RPC node",
        ),
      ).to.have.lengthOf(1);
    });

    it("fails closed where injection moves out of the reader's sight: merge keys, extends, secrets, hidden keys", function () {
      const merged = readServices(
        "synthetic.yml",
        [
          "x-deploy-env: &deploy-env",
          "  EXAMPLE: value",
          "services:",
          "  svc:",
          "    image: walletwall-vault:latest",
          `    command: ${NODE}`,
          "    environment:",
          "      <<: *deploy-env",
        ].join("\n"),
      ).services[0];
      expect(credentialFindings(merged, "JSON-RPC node")).to.include(
        "an anchor, alias or merge key brings in values this guard cannot see",
      );
      expect(credentialFindings(node("    extends:", "      service: vault-deploy"), "JSON-RPC node")).to.include(
        "extends: brings in values this guard cannot see",
      );
      expect(credentialFindings(node("    secrets: [deployer_key]"), "JSON-RPC node")).to.include(
        "secrets: brings in values this guard cannot see",
      );
      for (const hidden of [
        ["    ports:", '    - "8545:8545"'],
        ['    "env_file": .env'],
        ["    <<: *node-defaults"],
        ["    ports: [", '      "8545:8545"', "    ]"],
      ]) {
        const read = readServices(
          "synthetic.yml",
          ["services:", "  svc:", `    command: ${NODE}`, ...hidden].join("\n"),
        );
        const failsClosed = read.unmodeled.length > 0 || exposureFindings(read.services[0], "JSON-RPC node").length > 0;
        expect(failsClosed, hidden.join(" ")).to.equal(true);
      }
    });

    it("parses .dockerignore the way the build context does: the last match wins and ! re-includes", function () {
      expect(dockerignoreExcludes(".env", ".env")).to.equal(true);
      expect(dockerignoreExcludes("*.env", ".env")).to.equal(true);
      expect(dockerignoreExcludes("**/.env", ".env")).to.equal(true);
      expect(dockerignoreExcludes(".env\n!.env", ".env")).to.equal(false);
      expect(dockerignoreExcludes(".env.local\nnode_modules", ".env")).to.equal(false);
      // A pattern is a literal unless it wildcards: this is why `.env` alone leaves every sibling in the context.
      expect(dockerignoreExcludes(".env", ".env.local")).to.equal(false);
      expect(dockerignoreExcludes(".env*", ".env.local")).to.equal(true);
      expect(dockerignoreExcludes(".env*", ".env.example")).to.equal(true);
      // ...and why re-including the template has to come after the sweep, never before it.
      expect(dockerignoreExcludes(".env*\n!.env.example", ".env.example")).to.equal(false);
      expect(dockerignoreExcludes(".env*\n!.env.example", ".env.local")).to.equal(true);
      expect(dockerignoreExcludes("!.env.example\n.env*", ".env.example")).to.equal(true);
    });

    it("counts an environment read in each shape it is written, and a shell expansion only in a shell script", function () {
      for (const source of [
        'process.env.SEPOLIA_RPC_URL ?? "https://x"',
        'process.env["SEPOLIA_RPC_URL"]',
        "process.env[ 'SEPOLIA_RPC_URL' ]",
        'configVariable("SEPOLIA_RPC_URL")',
      ]) {
        expect(readsVariable("a.ts", source, "SEPOLIA_RPC_URL"), source).to.equal(true);
      }
      // A near miss must not count: a longer name that merely starts with this one, or a bare mention.
      expect(readsVariable("a.ts", "process.env.SEPOLIA_RPC_URL_FALLBACK", "SEPOLIA_RPC_URL")).to.equal(false);
      expect(readsVariable("a.ts", "// set SEPOLIA_RPC_URL in .env", "SEPOLIA_RPC_URL")).to.equal(false);
      // Shell expansion: honoured in .sh, ignored in .ts where it would match a template literal.
      for (const shell of ['RPC="${SEPOLIA_RPC_URL:-https://x}"', "echo $SEPOLIA_RPC_URL"]) {
        expect(readsVariable("a.sh", shell, "SEPOLIA_RPC_URL"), shell).to.equal(true);
        expect(readsVariable("a.ts", shell, "SEPOLIA_RPC_URL"), shell).to.equal(false);
      }
    });

    it("reports a deployment credential nothing reads, and stays silent about one a named source reads", function () {
      const deploy = (...environment: string[]): Service =>
        service(
          "    profiles: [deploy]",
          "    command: /bin/sh /app/scripts/deploy-entrypoint.sh",
          "    environment:",
          ...environment,
        );
      // hardhat.config.ts reads DEPLOYER_PRIVATE_KEY and the RPC URLs; nothing anywhere reads ETHERSCAN_API_KEY.
      expect(
        unconsumedCredentials(deploy("      - DEPLOYER_PRIVATE_KEY=${DEPLOYER_PRIVATE_KEY}"), ["hardhat.config.ts"]),
      ).to.deep.equal([]);
      expect(
        unconsumedCredentials(deploy("      - ETHERSCAN_API_KEY=${ETHERSCAN_API_KEY:-}"), ["hardhat.config.ts"]),
      ).to.have.lengthOf(1);
      // A name shaped like a credential counts even when it is not on the deployment list.
      expect(unconsumedCredentials(deploy("      - PINATA_API_KEY=x"), ["hardhat.config.ts"])).to.have.lengthOf(1);
      // An address the deploy script reads is fine; an unmodeled environment: fails closed.
      expect(
        unconsumedCredentials(deploy("      - PQC_VERIFIER_ADDRESS=${PQC_VERIFIER_ADDRESS:-}"), ["scripts"]),
      ).to.deep.equal([]);
      expect(
        unconsumedCredentials(service("    profiles: [deploy]", "    environment: ${INJECTED}"), ["hardhat.config.ts"]),
      ).to.have.lengthOf(1);
    });

    it("reads fenced blocks and joins a compose command continued across lines, ignoring prose between blocks", function () {
      const text = [
        "Run it:",
        "```bash",
        "cd /opt/walletwall-vault",
        "docker compose -f docker-compose.droplet.yml \\",
        "  --profile node up -d walletwall-node",
        "```",
        "docker compose up -d",
        "```bash",
        "docker compose down",
        "```",
      ].join("\n");
      const blocks = fencedBlocks(text);
      expect(blocks.map((block) => block.length)).to.deep.equal([3, 1]);
      expect(blocks[0].some(({ text: line }) => line.includes(DROPLET_DIRECTORY))).to.equal(true);
      expect(composeCommands(blocks[0])).to.deep.equal([
        { line: 4, command: "docker compose -f docker-compose.droplet.yml --profile node up -d walletwall-node" },
      ]);
      expect(composeCommands(blocks[1])).to.deep.equal([{ line: 9, command: "docker compose down" }]);
    });

    it("parses documented `docker run` publications across continued lines, without mistaking look-alike flags", function () {
      const text = [
        "docker run --rm -p 8545:8545 walletwall-vault:latest &",
        "docker run --rm \\",
        "  --publish=127.0.0.1:8545:8545 \\",
        "  --pq-signature-file sig.hex --public-key-file pk.hex walletwall-vault",
        "mkdir -p /opt/walletwall-vault",
      ].join("\n");
      expect(documentedPublications("doc.md", text)).to.deep.equal([
        { where: "doc.md:1", spec: "8545:8545" },
        { where: "doc.md:2", spec: "127.0.0.1:8545:8545" },
      ]);
    });
  });
});
