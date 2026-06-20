import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

function readDoc(path: string): string {
  return readFileSync(resolve(path), "utf8").toLowerCase().replace(/\s+/g, " ");
}

describe("public docs boundary language", function () {
  const readme = readDoc("README.md");
  const security = readDoc("SECURITY.md");
  const appBoundary = readDoc("docs/WALLETWALL_APP_BOUNDARY.md");
  const threatModel = readDoc("docs/THREAT_MODEL.md");
  const roadmap = readDoc("docs/ROADMAP.md");
  const testing = readDoc("docs/TESTING.md");

  it("README scopes production app behavior to read-only surfaces", function () {
    expect(readme).to.include("public walletwall production app surfaces remain read-only intelligence");
    expect(readme).to.include("isolated developer/testnet rehearsal path");
    expect(readme).to.include("not a mainnet write path");
  });

  it("README rejects production deposits, withdrawals, custody, and yield", function () {
    for (const phrase of [
      "do not accept real deposits",
      "process production withdrawals",
      "custody user funds",
      "real yield",
    ]) {
      expect(readme).to.include(phrase);
    }
  });

  it("SECURITY.md carries the production-service non-claims", function () {
    for (const phrase of [
      "does not provide a production deposit or withdrawal service",
      "does not custody user funds",
      "does not produce real yield",
      "does not include a mainnet production write path",
    ]) {
      expect(security).to.include(phrase);
    }
  });

  it("WalletWall app boundary isolates simulator paths from production app claims", function () {
    for (const phrase of [
      "production app surfaces remain read-only wallet intelligence",
      "isolated developer/testnet rehearsal exception",
      "not production app behavior",
      "not a production deposit/withdrawal service",
      "not real yield",
      "not a mainnet write path",
    ]) {
      expect(appBoundary).to.include(phrase);
    }
  });

  it("WalletWall app boundary blocks deposit, withdrawal, yield, and mainnet-write claims", function () {
    for (const phrase of [
      "a production deposit or withdrawal service",
      "a source of real yield",
      "a mainnet production write path",
      "users can deposit into walletwall for yield",
      "production withdrawals are live",
    ]) {
      expect(appBoundary).to.include(phrase);
    }
  });

  it("threat model keeps local/Sepolia flows prototype-scoped", function () {
    expect(threatModel).to.include("production app surfaces remain read-only");
    expect(threatModel).to.include("a production deposit or withdrawal service");
    expect(threatModel).to.include("a real-yield product");
    expect(threatModel).to.include("local and sepolia simulator paths are developer/testnet rehearsal exceptions only");
  });

  it("roadmap and testing docs avoid production-service overclaims", function () {
    expect(roadmap).to.include("not production custody");
    expect(roadmap).to.include("production deposit/withdrawal service");
    expect(roadmap).to.include("real yield");
    expect(testing).to.include("production deposits or withdrawals");
    expect(testing).to.include("yield");
  });
});
