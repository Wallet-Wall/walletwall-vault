/**
 * Tests for the hosted ZK adapter evidence endpoint: the pure handler/serializer/
 * validator (scripts/lib/zk-adapter-endpoint.ts), the committed example response
 * (evidence/zk/zk-adapter-evidence-response.example.json), and the JSON Schema.
 *
 * Pure, fast, static reads — no server, no network, no proving.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { keccak256, toUtf8Bytes } from "ethers";
import { expect } from "chai";

import {
  ZK_ADAPTER_RESPONSE_SCHEMA,
  ZK_ENDPOINT_MODE,
  ZK_ENDPOINT_SERVICE,
  ZK_ENDPOINT_STATUS,
  buildAdapterEvidenceResponse,
  computeAdapterETag,
  handleAdapterEvidenceRequest,
  isZKAdapterEvidenceResponse,
  validateAdapterEvidenceResponse,
  type ZKAdapterEvidenceResponse,
} from "../scripts/lib/zk-adapter-endpoint";
import { validateAdapter, type ZKVerifierAdapter } from "../scripts/lib/zk-verifier-adapter";
import {
  RESPONSE_PATH,
  buildExampleResponse,
  loadCommittedAdapter,
} from "../scripts/generate-zk-adapter-evidence-response";

const schemaPath = resolve("evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json");

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function adapter(): ZKVerifierAdapter {
  return loadCommittedAdapter();
}

function freshValid(): ZKAdapterEvidenceResponse {
  return JSON.parse(JSON.stringify(buildExampleResponse()));
}

describe("hosted ZK adapter evidence endpoint", function () {
  describe("buildAdapterEvidenceResponse / validate", function () {
    it("builds a 200 response that validates and serves a valid adapter", function () {
      const res = validateAdapterEvidenceResponse(buildExampleResponse());
      expect(res.errors).to.deep.equal([]);
      expect(res.valid).to.equal(true);
      expect(validateAdapter(buildExampleResponse().adapter).valid).to.equal(true);
    });

    it("exposes a type guard", function () {
      expect(isZKAdapterEvidenceResponse(buildExampleResponse())).to.equal(true);
      expect(isZKAdapterEvidenceResponse({})).to.equal(false);
    });

    it("stamps a fresh ISO servedAt by default and a strong etag", function () {
      const r = buildAdapterEvidenceResponse(adapter());
      expect(r.servedAt).to.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/);
      expect(r.etag).to.equal(keccak256(toUtf8Bytes(JSON.stringify(adapter()))));
    });
  });

  describe("handleAdapterEvidenceRequest (conditional GET)", function () {
    const a = adapter();
    const etag = computeAdapterETag(a);

    it("returns 200 with the adapter for a plain GET", function () {
      const r = handleAdapterEvidenceRequest({ method: "GET" }, a, { now: "2026-01-01T00:00:00.000Z" });
      expect(r.status).to.equal(ZK_ENDPOINT_STATUS.OK);
      expect(r.ok).to.equal(true);
      expect((r as ZKAdapterEvidenceResponse).etag).to.equal(etag);
    });

    it("treats a missing method as GET", function () {
      expect(handleAdapterEvidenceRequest({}, a).status).to.equal(ZK_ENDPOINT_STATUS.OK);
    });

    it("returns 304 (no body) when ifNoneMatch matches the etag", function () {
      const r = handleAdapterEvidenceRequest({ method: "GET", ifNoneMatch: etag }, a);
      expect(r.status).to.equal(ZK_ENDPOINT_STATUS.NOT_MODIFIED);
      expect(r.ok).to.equal(true);
      expect((r as unknown as Record<string, unknown>).adapter).to.equal(undefined);
    });

    it("returns 200 when ifNoneMatch is a stale etag", function () {
      const r = handleAdapterEvidenceRequest({ ifNoneMatch: "0x" + "00".repeat(32) }, a);
      expect(r.status).to.equal(ZK_ENDPOINT_STATUS.OK);
    });

    it("returns 405 for a non-GET method", function () {
      const r = handleAdapterEvidenceRequest({ method: "POST" }, a);
      expect(r.status).to.equal(ZK_ENDPOINT_STATUS.METHOD_NOT_ALLOWED);
      expect(r.ok).to.equal(false);
    });

    it("returns 400 for an unknown request field", function () {
      const r = handleAdapterEvidenceRequest({ method: "GET", body: "x" }, a);
      expect(r.status).to.equal(ZK_ENDPOINT_STATUS.BAD_REQUEST);
      expect(r.ok).to.equal(false);
    });

    it("returns 400 for a non-object request", function () {
      expect(handleAdapterEvidenceRequest(null, a).status).to.equal(ZK_ENDPOINT_STATUS.BAD_REQUEST);
      expect(handleAdapterEvidenceRequest([], a).status).to.equal(ZK_ENDPOINT_STATUS.BAD_REQUEST);
    });
  });

  describe("validateAdapterEvidenceResponse — rejects", function () {
    it("a wrong schema id", function () {
      const r = freshValid();
      r.schema = "walletwall.zk-adapter-evidence-response.v2" as never;
      expect(validateAdapterEvidenceResponse(r).valid).to.equal(false);
    });

    it("an unknown top-level key", function () {
      const r = freshValid() as unknown as Record<string, unknown>;
      r.surprise = 1;
      const res = validateAdapterEvidenceResponse(r);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/unexpected key in response/);
    });

    it("a non-200 status", function () {
      const r = freshValid();
      r.status = 304 as never;
      expect(validateAdapterEvidenceResponse(r).valid).to.equal(false);
    });

    it("an etag that is not keccak256 of the adapter", function () {
      const r = freshValid();
      r.etag = "0x" + "00".repeat(32);
      const res = validateAdapterEvidenceResponse(r);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/etag must be keccak256 of the served adapter/);
    });

    it("an invalid embedded adapter (bubbles validateAdapter errors)", function () {
      const r = freshValid();
      (r.adapter.onChainVerifier as unknown as Record<string, unknown>).onChainVerification = true;
      const res = validateAdapterEvidenceResponse(r);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/adapter\./);
    });

    it("a malformed servedAt", function () {
      const r = freshValid();
      r.servedAt = "later";
      expect(validateAdapterEvidenceResponse(r).valid).to.equal(false);
    });

    it("a limitations list missing a required disclosure topic", function () {
      const r = freshValid();
      r.limitations = r.limitations.filter((l) => !/read-only/i.test(l));
      const res = validateAdapterEvidenceResponse(r);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/limitations must disclose: read-only/);
    });

    it("overclaim language on an asserted (non-limitations, non-adapter) field", function () {
      const r = freshValid() as unknown as Record<string, unknown>;
      (r.regeneration as Record<string, unknown>).command = "npm run production-ready guaranteed";
      const res = validateAdapterEvidenceResponse(r);
      expect(res.valid).to.equal(false);
      expect(res.errors.join(" ")).to.match(/overclaim language/);
    });
  });

  describe("committed example (no drift, serves the committed adapter)", function () {
    it("the committed file equals the freshly generated example", function () {
      expect(readJson(RESPONSE_PATH)).to.deep.equal(buildExampleResponse());
    });

    it("the committed file validates", function () {
      expect(validateAdapterEvidenceResponse(readJson(RESPONSE_PATH)).valid).to.equal(true);
    });

    it("serves exactly the committed adapter, with a matching etag", function () {
      const r = readJson(RESPONSE_PATH) as ZKAdapterEvidenceResponse;
      expect(JSON.stringify(r.adapter)).to.equal(JSON.stringify(loadCommittedAdapter()));
      expect(r.etag).to.equal(computeAdapterETag(loadCommittedAdapter()));
    });

    it("a conditional GET with the committed etag yields 304", function () {
      const r = readJson(RESPONSE_PATH) as ZKAdapterEvidenceResponse;
      const conditional = handleAdapterEvidenceRequest({ method: "GET", ifNoneMatch: r.etag }, loadCommittedAdapter());
      expect(conditional.status).to.equal(304);
    });

    it("is deterministic across rebuilds", function () {
      expect(JSON.stringify(buildExampleResponse())).to.equal(JSON.stringify(buildExampleResponse()));
    });
  });

  describe("JSON Schema stays in sync with the code", function () {
    const schema = readJson(schemaPath) as Record<string, any>;

    it("response schema const matches ZK_ADAPTER_RESPONSE_SCHEMA", function () {
      expect(schema.properties.schema.const).to.equal(ZK_ADAPTER_RESPONSE_SCHEMA);
    });

    it("service / mode consts match the code", function () {
      expect(schema.properties.service.const).to.equal(ZK_ENDPOINT_SERVICE);
      expect(schema.properties.mode.const).to.equal(ZK_ENDPOINT_MODE);
    });

    it("status const matches the OK status", function () {
      expect(schema.properties.status.const).to.equal(ZK_ENDPOINT_STATUS.OK);
    });

    it("the committed example's top-level keys equal the schema's required set", function () {
      const response = readJson(RESPONSE_PATH) as Record<string, unknown>;
      expect(Object.keys(response).sort()).to.deep.equal([...schema.required].sort());
    });
  });
});
