/**
 * Tests for the canonical PQ algorithm standards registry
 * (src/standards/pq-algorithm-registry.ts).
 *
 * Coverage: canonical ML-DSA-65 record shape, ML-KEM and SLH-DSA are
 * explicitly not-implemented, registry-wide invariants (nothing is
 * "validated" today, "not-implemented" algorithms carry no implementation
 * details), and the derived standards-alignment status model.
 */
import { expect } from "chai";

import {
  PQ_ALGORITHM_IDS,
  PQ_CERTIFICATION_STATUSES,
  PQ_ALGORITHM_REGISTRY,
  getPQAlgorithmRecord,
  getPQStandardsAlignmentStatus,
  isPQAlgorithmImplemented,
} from "../src/standards/pq-algorithm-registry";

describe("PQ algorithm registry", function () {
  describe("ML-DSA-65 (implemented)", function () {
    const record = getPQAlgorithmRecord("ML-DSA");

    it("identifies the algorithm, parameter set, standard, and purpose correctly", function () {
      expect(record.algorithm).to.equal("ML-DSA");
      expect(record.parameterSet).to.equal("ML-DSA-65");
      expect(record.standard).to.equal("FIPS 204");
      expect(record.purpose).to.equal("signature");
    });

    it("records the actual implementation package and pinned version", function () {
      expect(record.implementation.package).to.equal("@noble/post-quantum");
      expect(record.implementation.version).to.equal("0.6.1");
      expect(record.implementation.provider).to.be.a("string").and.not.empty;
    });

    it("is marked implemented, with real verification modes", function () {
      expect(record.implementationStatus).to.equal("implemented");
      expect(record.verificationModes).to.include("off-chain");
      expect(record.verificationModes.length).to.be.greaterThan(0);
    });

    it("reflects the committed conformance surface honestly (not the full 15/15 group)", function () {
      expect(record.conformanceStatus).to.equal("vectors-tested");
    });

    it("is NOT validated and is scoped as a prototype", function () {
      expect(record.certificationStatus).to.equal("not-validated");
      expect(record.productionStatus).to.not.equal("production");
    });
  });

  for (const [id, purpose, standard] of [
    ["ML-KEM", "key-establishment", "FIPS 203"],
    ["SLH-DSA", "signature", "FIPS 205"],
  ] as const) {
    describe(`${id} (not implemented)`, function () {
      const record = getPQAlgorithmRecord(id);

      it(`is explicitly not-implemented, with standard ${standard} and purpose ${purpose}`, function () {
        expect(record.implementationStatus).to.equal("not-implemented");
        expect(record.standard).to.equal(standard);
        expect(record.purpose).to.equal(purpose);
      });

      it("carries no implementation details and no verification modes", function () {
        expect(record.implementation.provider).to.equal(null);
        expect(record.implementation.package).to.equal(null);
        expect(record.implementation.version).to.equal(null);
        expect(record.verificationModes).to.deep.equal([]);
      });

      it("is not-validated and research-only — absence is never a positive claim", function () {
        expect(record.certificationStatus).to.equal("not-validated");
        expect(record.productionStatus).to.equal("research-only");
      });

      it(`isPQAlgorithmImplemented("${id}") is false`, function () {
        expect(isPQAlgorithmImplemented(id)).to.equal(false);
      });
    });
  }

  describe("registry-wide invariants", function () {
    it("has exactly the three audited algorithm ids, no more, no fewer", function () {
      expect(Object.keys(PQ_ALGORITHM_REGISTRY).sort()).to.deep.equal([...PQ_ALGORITHM_IDS].sort());
    });

    it("nothing in the registry is certified/validated today", function () {
      for (const id of PQ_ALGORITHM_IDS) {
        expect(getPQAlgorithmRecord(id).certificationStatus).to.equal("not-validated");
      }
    });

    it("only ML-DSA is implemented; ML-KEM and SLH-DSA are not", function () {
      expect(isPQAlgorithmImplemented("ML-DSA")).to.equal(true);
      expect(isPQAlgorithmImplemented("ML-KEM")).to.equal(false);
      expect(isPQAlgorithmImplemented("SLH-DSA")).to.equal(false);
    });

    it("PQ_CERTIFICATION_STATUSES includes a real 'validated' option (the field is not a permanent no-op)", function () {
      // The registry must be able to represent a genuinely validated algorithm
      // in the future; today's records simply don't claim it yet.
      expect(PQ_CERTIFICATION_STATUSES).to.include("validated");
    });
  });

  describe("getPQStandardsAlignmentStatus", function () {
    const status = getPQStandardsAlignmentStatus();

    it("signatureStandard reflects ML-DSA-65: implemented, evidence available, not validated", function () {
      expect(status.signatureStandard.algorithm).to.equal("ML-DSA");
      expect(status.signatureStandard.parameterSet).to.equal("ML-DSA-65");
      expect(status.signatureStandard.implemented).to.equal(true);
      expect(status.signatureStandard.evidenceAvailable).to.equal(true);
      expect(status.signatureStandard.validated).to.equal(false);
    });

    it("keyEstablishmentStandard (ML-KEM) is not implemented", function () {
      expect(status.keyEstablishmentStandard.algorithm).to.equal("ML-KEM");
      expect(status.keyEstablishmentStandard.implemented).to.equal(false);
      expect(status.keyEstablishmentStandard.validated).to.equal(false);
    });

    it("alternateSignatureStandard (SLH-DSA) is not implemented", function () {
      expect(status.alternateSignatureStandard.algorithm).to.equal("SLH-DSA");
      expect(status.alternateSignatureStandard.implemented).to.equal(false);
      expect(status.alternateSignatureStandard.validated).to.equal(false);
    });

    it("is not a percentage/score — no numeric readiness field exists on the status object", function () {
      const flat = JSON.stringify(status);
      expect(flat).to.not.match(/"score"|"percent"|"readinessScore"/i);
    });
  });
});
