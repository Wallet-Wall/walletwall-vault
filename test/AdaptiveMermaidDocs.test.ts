import { expect } from "chai";
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

interface AdaptiveDiagram {
  file: string;
  source: string;
  light: string;
  dark: string;
}

interface AdaptiveManifest {
  count: number;
  diagrams: AdaptiveDiagram[];
}

describe("adaptive Mermaid documentation", function () {
  const manifest = JSON.parse(
    readFileSync(resolve("docs/diagrams/adaptive-manifest.json"), "utf8"),
  ) as AdaptiveManifest;

  it("covers all 13 remaining native Mermaid diagrams", function () {
    expect(manifest.count).to.equal(13);
    expect(manifest.diagrams).to.have.length(13);
  });

  for (const entry of manifest.diagrams) {
    it(`${entry.file} links transparent light and dark assets`, function () {
      const page = readFileSync(resolve(entry.file), "utf8");
      const source = readFileSync(resolve(entry.source), "utf8");
      const lightRef = relative(dirname(entry.file), entry.light).replaceAll("\\", "/");
      const darkRef = relative(dirname(entry.file), entry.dark).replaceAll("\\", "/");
      const sourceRef = relative(dirname(entry.file), entry.source).replaceAll("\\", "/");

      expect(page).not.to.match(/```mermaid/i);
      expect(page).to.include("<picture>");
      expect(page).to.include(lightRef);
      expect(page).to.include(darkRef);
      expect(page).to.include(sourceRef);
      expect(source.trim()).not.to.equal("");

      for (const asset of [entry.light, entry.dark]) {
        expect(existsSync(resolve(asset)), `${asset} must exist`).to.equal(true);
        const svg = readFileSync(resolve(asset), "utf8");
        expect(svg).to.match(/^<svg\b/);
        expect(svg).to.match(/viewBox="[^"]+"/);
        expect(svg).to.match(/background-color:\s*transparent/i);
        expect(svg).not.to.match(/<script\b/i);
      }
    });
  }
});
