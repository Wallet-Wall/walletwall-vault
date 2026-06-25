//! Offline, deterministic evidence-shape + ETag-parity validator — Phase 1 crate.
//!
//! SCAFFOLD / OFFLINE ONLY.
//!
//! This library takes a committed evidence JSON artifact (already loaded into a
//! string by the caller) and checks its deterministic *shape* against the
//! `walletwall.zk-adapter-evidence-response.v1` response contract documented in
//! `docs/ZK_Adapter_Evidence_Endpoint.md` and pinned by
//! `evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json`, and then
//! cross-checks the canonical keccak256 `etag` for deterministic *parity*.
//!
//! What this validates (deterministic contract shape):
//!   * every required top-level field is present and well-typed,
//!   * no unknown top-level fields are present (`deny_unknown_fields`,
//!     mirroring the schema's `additionalProperties: false`),
//!   * the fixed-constant fields hold their contract values,
//!   * `status` and `ok` are internally consistent (a 2xx status requires
//!     `ok == true`; a non-2xx status requires `ok == false`),
//!   * `servedAt` is an ISO-8601 UTC timestamp of the contracted form, with
//!     in-range calendar/time components,
//!   * `etag` is a present, non-empty `0x` + 64 lowercase-hex string,
//!   * the embedded `adapter` is an object that carries its required identity /
//!     version fields (`schema` + `artifactType` contract constants),
//!   * `limitations` is a non-empty array of non-empty strings,
//!   * `regeneration` is present and carries a non-empty `command` and
//!     `deterministic == true`.
//!
//! What this validates (canonical ETag / keccak256 parity):
//!   * when the `etag` is well-formed (`0x` + 64 lowercase hex) and the embedded
//!     `adapter` carries its correct identity, the validator recomputes the
//!     canonical keccak256 content hash of the adapter — exactly as the
//!     TypeScript serializer does (`keccak256(JSON.stringify(adapter))`, compact
//!     and in document key order) — and fails validation if it does not equal the
//!     committed `etag`. This catches a tampered `etag`, a drifted adapter payload
//!     with a stale `etag`, and a re-ordered adapter that no longer hashes to the
//!     committed value.
//!
//! This ETag parity is an OFFLINE DETERMINISTIC cross-check, not a cryptographic
//! truth claim. It asserts only that the committed `etag` is the keccak256 of the
//! committed `adapter`. It is NOT proof verification, makes NO claim about chain
//! state, generates NO proof, runs NO prover, and touches NO network or chain.
//! The TypeScript `validate:zk-response` pass remains the CI source of truth; this
//! crate adds an independent, offline, second check and relaxes nothing.
//!
//! What this deliberately does NOT do:
//!   * It does NOT validate the embedded `adapter` in depth — only its top-level
//!     identity/version fields (plus the whole-adapter ETag hash). Deep adapter
//!     validation (`proofInput`, `journal`, `proof`, `evidence`, …) stays in
//!     TypeScript (`validateAdapter`); re-deriving it field-by-field in Rust is
//!     deferred, not implemented.
//!   * It performs NO network I/O, NO prover execution, NO SP1 SDK build, NO
//!     signing, NO key access, and NO chain access.
//!
//! See `docs/Rust_Evidence_Validator_Etag_Parity.md`,
//! `docs/Rust_Evidence_Validator_Contract_Expansion.md`,
//! `docs/Rust_Evidence_Tooling_Scaffold.md`, and the Phase 1 section of
//! `docs/Rust_Implementation_Path.md`.

// This scaffold has no need for `unsafe`; forbid it outright so the boundary is
// machine-checked, not just documented.
#![forbid(unsafe_code)]

use serde::Deserialize;
use sha3::{Digest, Keccak256};

/// Contract constants for `walletwall.zk-adapter-evidence-response.v1`.
pub const EXPECTED_SCHEMA: &str = "walletwall.zk-adapter-evidence-response.v1";
pub const EXPECTED_SERVICE: &str = "walletwall-zk-adapter-evidence-demo";
pub const EXPECTED_MODE: &str = "spike-non-production";
pub const EXPECTED_CONTENT_TYPE: &str = "application/json";
pub const EXPECTED_STATUS: u64 = 200;

/// Identity / version constants for the embedded `walletwall.zk-verifier-adapter.v1`
/// boundary. Only these top-level identity fields are checked here; the deep
/// adapter shape stays the TypeScript `validateAdapter` pass's responsibility.
pub const EXPECTED_ADAPTER_SCHEMA: &str = "walletwall.zk-verifier-adapter.v1";
pub const EXPECTED_ADAPTER_ARTIFACT_TYPE: &str = "zk-verifier-adapter-boundary";

/// Strict typed view of the response top level. `deny_unknown_fields` mirrors the
/// schema's `additionalProperties: false`; missing or mistyped fields are
/// rejected by serde before any value check runs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceResponse {
    schema: String,
    service: String,
    mode: String,
    status: u64,
    ok: bool,
    #[serde(rename = "contentType")]
    content_type: String,
    #[serde(rename = "servedAt")]
    served_at: String,
    etag: String,
    /// Validated only as "is an object" here; deep validation stays in TypeScript.
    adapter: serde_json::Value,
    limitations: Vec<String>,
    regeneration: Regeneration,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Regeneration {
    command: String,
    deterministic: bool,
}

/// Outcome of an offline shape-validation pass.
#[derive(Debug)]
pub struct ValidationOutcome {
    /// True only when zero shape problems were found.
    pub ok: bool,
    /// Human-readable problems; empty when `ok` is true.
    pub problems: Vec<String>,
}

impl ValidationOutcome {
    fn failure(problem: impl Into<String>) -> Self {
        ValidationOutcome {
            ok: false,
            problems: vec![problem.into()],
        }
    }
}

/// Validate the deterministic shape of an evidence-response JSON document.
///
/// This is an offline shape check only. It makes no cryptographic truth claim and
/// touches no network, prover, key, or chain.
pub fn validate_evidence_response(json: &str) -> ValidationOutcome {
    // Stage 1 — reject anything that is not valid JSON at all.
    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(value) => value,
        Err(err) => {
            return ValidationOutcome::failure(format!("not valid JSON: {err}"));
        }
    };

    // Stage 2 — enforce required fields, field types, and the closed top-level
    // shape (`deny_unknown_fields`). serde stops at the first structural problem.
    let parsed: EvidenceResponse = match serde_json::from_value(value) {
        Ok(parsed) => parsed,
        Err(err) => {
            return ValidationOutcome::failure(format!("evidence-response shape mismatch: {err}"));
        }
    };

    // Stage 3 — collect every contract-value problem; do not stop at the first.
    let mut problems: Vec<String> = Vec::new();

    if parsed.schema != EXPECTED_SCHEMA {
        problems.push("schema must be the contract value".to_string());
    }
    if parsed.service != EXPECTED_SERVICE {
        problems.push("service must be the contract value".to_string());
    }
    if parsed.mode != EXPECTED_MODE {
        problems.push("mode must be the contract value".to_string());
    }
    if parsed.status != EXPECTED_STATUS {
        problems.push("status must be 200".to_string());
    }
    if !parsed.ok {
        problems.push("ok must be true".to_string());
    }
    // Cross-field invariant: a 2xx status must carry `ok == true`, and any
    // non-2xx status must carry `ok == false`. This is internal-consistency
    // defense-in-depth on top of the pinned `status == 200` / `ok == true`
    // constants; it catches a `status`/`ok` pair that disagrees.
    if is_success_status(parsed.status) != parsed.ok {
        problems.push("ok is inconsistent with status (2xx requires ok=true)".to_string());
    }
    if parsed.content_type != EXPECTED_CONTENT_TYPE {
        problems.push("contentType must be application/json".to_string());
    }
    if !is_iso8601_utc(&parsed.served_at) {
        problems.push("servedAt must be an in-range ISO-8601 UTC timestamp".to_string());
    }
    if parsed.etag.is_empty() {
        problems.push("etag must be present and non-empty".to_string());
    } else if !is_strong_etag(&parsed.etag) {
        problems.push("etag must match ^0x[0-9a-f]{64}$".to_string());
    }
    let adapter_identity_ok = check_adapter_identity(&parsed.adapter, &mut problems);
    if parsed.limitations.is_empty() {
        problems.push("limitations must be a non-empty array".to_string());
    }
    for (index, item) in parsed.limitations.iter().enumerate() {
        if item.trim().is_empty() {
            problems.push(format!("limitations[{index}] must be a non-empty string"));
        }
    }
    if parsed.regeneration.command.trim().is_empty() {
        problems.push("regeneration.command must be a non-empty string".to_string());
    }
    if !parsed.regeneration.deterministic {
        problems.push("regeneration.deterministic must be true".to_string());
    }

    // Stage 4 — canonical ETag / keccak256 parity.
    //
    // Recompute the canonical keccak256 content hash of the embedded adapter and
    // require it to equal the committed `etag`. This is gated behind a well-formed
    // (`0x` + 64 lowercase hex) `etag` and a structurally credible adapter
    // identity: if the `etag` shape is already wrong, or the adapter is not an
    // object with the right identity, the parity recompute would only restate a
    // problem already reported, so it is skipped. This mirrors the TypeScript
    // `validate:zk-response` pass, which only cross-checks the hash once the
    // adapter itself is valid.
    //
    // This is an OFFLINE DETERMINISTIC parity check, not a cryptographic truth
    // claim: it asserts the committed `etag` is keccak256 of the committed
    // `adapter`, nothing more. No proof, no prover, no network, no chain.
    if is_strong_etag(&parsed.etag) && adapter_identity_ok {
        let expected = compute_adapter_etag(&parsed.adapter);
        if parsed.etag != expected {
            problems.push(format!(
                "etag does not match keccak256 of the canonical adapter JSON (expected {expected})"
            ));
        }
    }

    ValidationOutcome {
        ok: problems.is_empty(),
        problems,
    }
}

/// Recompute the strong ETag of an adapter exactly as the TypeScript serializer
/// does: keccak256 over the compact (`JSON.stringify`) UTF-8 bytes of the adapter
/// in document key order, rendered as `0x` + 64 lowercase hex.
///
/// `serde_json` is built here with the `preserve_order` feature, so a parsed
/// adapter re-serializes with its keys in document/insertion order and compact
/// separators — byte-for-byte equal to JavaScript `JSON.stringify(adapter)` for
/// this artifact family (no floats; only standard JSON escaping).
///
/// This is an OFFLINE DETERMINISTIC recomputation, not a cryptographic truth
/// claim and not proof verification. It only restates, in Rust, the content-hash
/// identity the TypeScript `computeAdapterETag` defines.
pub fn compute_adapter_etag(adapter: &serde_json::Value) -> String {
    use std::fmt::Write as _;

    // A `serde_json::Value` re-serializes infallibly: object keys are always
    // strings and JSON numbers are never NaN/Inf, so there is nothing to error on.
    let canonical = serde_json::to_string(adapter)
        .expect("a serde_json::Value always serializes back to a JSON string");
    let digest = Keccak256::digest(canonical.as_bytes());

    let mut etag = String::with_capacity(2 + 64);
    etag.push_str("0x");
    for byte in digest {
        let _ = write!(etag, "{byte:02x}");
    }
    etag
}

/// `^0x[0-9a-f]{64}$` — a strong lowercase-hex content-hash ETag.
///
/// This is a SHAPE check only. The separate Stage-4 parity step is what recomputes
/// keccak256 and asserts the hash is correct for the embedded adapter; this helper
/// just gates that step behind a well-formed ETag.
fn is_strong_etag(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True for an HTTP-like 2xx success status.
fn is_success_status(status: u64) -> bool {
    (200..300).contains(&status)
}

/// Check the embedded `adapter`'s required identity / version fields against the
/// `walletwall.zk-verifier-adapter.v1` contract constants.
///
/// This is a SHALLOW identity check only: it confirms the adapter is an object
/// carrying the right `schema` + `artifactType` constants, so a wrong or stub
/// adapter cannot pass unnoticed. It does NOT deeply validate the adapter
/// (`proofInput`, `journal`, `proof`, `evidence`, …); that stays the authoritative
/// TypeScript `validateAdapter` pass's responsibility.
///
/// Returns `true` only when the adapter is an object whose `schema` and
/// `artifactType` both equal their contract constants. The ETag-parity recompute
/// is gated on this so a structurally wrong adapter does not produce a redundant
/// (and misleading) second hash-mismatch problem.
fn check_adapter_identity(adapter: &serde_json::Value, problems: &mut Vec<String>) -> bool {
    let Some(object) = adapter.as_object() else {
        problems.push("adapter must be a JSON object".to_string());
        return false;
    };

    let schema_ok = check_identity_field(object, "schema", EXPECTED_ADAPTER_SCHEMA, problems);
    let artifact_type_ok = check_identity_field(
        object,
        "artifactType",
        EXPECTED_ADAPTER_ARTIFACT_TYPE,
        problems,
    );
    schema_ok && artifact_type_ok
}

/// Check that one adapter identity/version field is present, a string, and equal
/// to its contract constant; push a precise problem otherwise. Returns whether the
/// field held its contract value.
fn check_identity_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    expected: &str,
    problems: &mut Vec<String>,
) -> bool {
    match object.get(field).and_then(serde_json::Value::as_str) {
        Some(value) if value == expected => true,
        Some(_) => {
            problems.push(format!("adapter.{field} must be the contract value"));
            false
        }
        None => {
            problems.push(format!("adapter.{field} must be present and a string"));
            false
        }
    }
}

/// Accept exactly `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.mmmZ` — the two
/// forms the contract's `servedAt` pattern allows — AND require the calendar/time
/// components to be in range (month `01`–`12`, day `01`–`31`, hour `00`–`23`,
/// minute `00`–`59`, second `00`–`59`).
///
/// This is a deterministic structural + component-range check. It is NOT a full
/// calendar validator: it does not reject day-of-month overflow for short months
/// (e.g. `02-30`) or leap-year edge cases. The authoritative TypeScript
/// `Date.parse` cross-check stays the source of truth for full parseability.
fn is_iso8601_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    let has_millis = match bytes.len() {
        20 => false,
        24 => true,
        _ => return false,
    };

    // Date: YYYY-MM-DD
    if !all_ascii_digits(bytes, 0, 4) || bytes[4] != b'-' {
        return false;
    }
    if !all_ascii_digits(bytes, 5, 2) || bytes[7] != b'-' {
        return false;
    }
    if !all_ascii_digits(bytes, 8, 2) {
        return false;
    }

    // `T` separator, then time HH:MM:SS.
    if bytes[10] != b'T' {
        return false;
    }
    if !all_ascii_digits(bytes, 11, 2) || bytes[13] != b':' {
        return false;
    }
    if !all_ascii_digits(bytes, 14, 2) || bytes[16] != b':' {
        return false;
    }
    if !all_ascii_digits(bytes, 17, 2) {
        return false;
    }

    // Optional `.mmm` fraction, then `Z`.
    let terminator_ok = if has_millis {
        bytes[19] == b'.' && all_ascii_digits(bytes, 20, 3) && bytes[23] == b'Z'
    } else {
        bytes[19] == b'Z'
    };
    if !terminator_ok {
        return false;
    }

    // Component ranges. Year and the optional millisecond fraction accept any
    // digits; the remaining fields must fall in their calendar/clock ranges.
    let month = two_digits(bytes, 5);
    let day = two_digits(bytes, 8);
    let hour = two_digits(bytes, 11);
    let minute = two_digits(bytes, 14);
    let second = two_digits(bytes, 17);

    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

/// True when `bytes[start..start + len]` are all ASCII digits. Callers guarantee
/// the range is in bounds.
fn all_ascii_digits(bytes: &[u8], start: usize, len: usize) -> bool {
    bytes[start..start + len].iter().all(u8::is_ascii_digit)
}

/// Read the two ASCII digits at `bytes[start..start + 2]` as a number. Callers
/// guarantee the two bytes are ASCII digits and in bounds.
fn two_digits(bytes: &[u8], start: usize) -> u32 {
    u32::from(bytes[start] - b'0') * 10 + u32::from(bytes[start + 1] - b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    // All fixtures are local, checked-in scaffold test material — NOT canonical
    // evidence artifacts. The canonical artifact lives at
    // evidence/zk/zk-adapter-evidence-response.example.json and is owned by the
    // TypeScript validators; these fixtures only exercise this shape checker.
    const VALID: &str = include_str!("../fixtures/zk-adapter-evidence-response.valid.json");
    const MALFORMED: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-malformed-json.json");
    const MISSING_ETAG: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-missing-etag.json");
    const UNKNOWN_FIELD: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-unknown-field.json");
    const WRONG_SCHEMA: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-wrong-schema.json");
    const BAD_ETAG: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-bad-etag.json");
    const EMPTY_LIMITATIONS: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-empty-limitations.json");
    const WRONG_STATUS: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-wrong-status.json");
    const WRONG_SERVICE: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-wrong-service.json");
    const STATUS_OK_MISMATCH: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-status-ok-mismatch.json");
    const MISSING_LIMITATIONS: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-missing-limitations.json");
    const MISSING_REGENERATION: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-missing-regeneration.json");
    const BAD_TIMESTAMP: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-bad-timestamp.json");
    const EMPTY_ETAG: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-empty-etag.json");
    const MALFORMED_ADAPTER: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-malformed-adapter.json");
    const ADAPTER_MISSING_IDENTITY: &str = include_str!(
        "../fixtures/zk-adapter-evidence-response.invalid-adapter-missing-identity.json"
    );
    const ADAPTER_WRONG_IDENTITY: &str = include_str!(
        "../fixtures/zk-adapter-evidence-response.invalid-adapter-wrong-identity.json"
    );
    // ETag / keccak256 parity fixtures (local scaffold material).
    const ETAG_MISMATCH: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-etag-mismatch.json");
    const ETAG_STALE_ADAPTER: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-etag-stale-adapter.json");
    const ETAG_NONCANONICAL_ORDER: &str = include_str!(
        "../fixtures/zk-adapter-evidence-response.invalid-etag-noncanonical-order.json"
    );
    const ETAG_UPPERCASE: &str =
        include_str!("../fixtures/zk-adapter-evidence-response.invalid-etag-uppercase.json");

    #[test]
    fn accepts_the_valid_fixture() {
        let outcome = validate_evidence_response(VALID);
        assert!(
            outcome.ok,
            "valid fixture should pass: {:?}",
            outcome.problems
        );
        assert!(outcome.problems.is_empty());
    }

    #[test]
    fn rejects_malformed_json() {
        let outcome = validate_evidence_response(MALFORMED);
        assert!(!outcome.ok);
        assert!(outcome.problems[0].contains("not valid JSON"));
    }

    #[test]
    fn rejects_missing_required_field() {
        // `etag` is absent — serde rejects it at the typed-shape stage.
        let outcome = validate_evidence_response(MISSING_ETAG);
        assert!(!outcome.ok);
        assert!(outcome.problems[0].contains("shape"));
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        // An extra top-level key is rejected by `deny_unknown_fields`.
        let outcome = validate_evidence_response(UNKNOWN_FIELD);
        assert!(!outcome.ok);
        assert!(outcome.problems[0].contains("shape"));
    }

    #[test]
    fn rejects_wrong_schema_constant() {
        let outcome = validate_evidence_response(WRONG_SCHEMA);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("schema must be")));
    }

    #[test]
    fn rejects_bad_etag() {
        let outcome = validate_evidence_response(BAD_ETAG);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag must match")));
    }

    #[test]
    fn rejects_empty_limitations() {
        let outcome = validate_evidence_response(EMPTY_LIMITATIONS);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("non-empty array")));
    }

    #[test]
    fn rejects_wrong_status() {
        let outcome = validate_evidence_response(WRONG_STATUS);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("status must be")));
    }

    #[test]
    fn loads_the_valid_fixture_from_disk() {
        // Exercises the on-disk read path the CLI uses, with a checked-in local
        // fixture resolved relative to the crate, not the process CWD.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{manifest_dir}/fixtures/zk-adapter-evidence-response.valid.json");
        let contents = std::fs::read_to_string(&path).expect("read the valid fixture from disk");
        assert!(validate_evidence_response(&contents).ok);
    }

    #[test]
    fn rejects_a_swapped_but_well_shaped_etag() {
        // The valid fixture passes parity; swapping in a different, still
        // well-shaped (`0x` + 64 lowercase hex) etag must now FAIL the keccak256
        // parity check. This is the offline deterministic content-hash cross-check
        // — not a cryptographic truth claim, no proof, no prover, no chain.
        assert!(validate_evidence_response(VALID).ok);
        let swapped = VALID.replace(
            "0x98fb94cfd69a4c962501f10a581656437d11edd5419426c019a0bcdd628d4375",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        let outcome = validate_evidence_response(&swapped);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag does not match keccak256 of the canonical adapter JSON")));
    }

    #[test]
    fn compute_adapter_etag_is_zero_x_64_lowercase_hex() {
        // Format guard for the recompute helper: its output is itself a strong
        // (`0x` + 64 lowercase hex) ETag, i.e. exactly what the shape check accepts.
        let adapter = serde_json::json!({ "any": "object", "n": 1 });
        let etag = compute_adapter_etag(&adapter);
        assert_eq!(etag.len(), 66);
        assert!(is_strong_etag(&etag));
    }

    #[test]
    fn recomputes_the_canonical_typescript_example_etag() {
        // The cross-language parity assertion: the Rust keccak256 of the canonical
        // example's embedded adapter must equal the `etag` the TypeScript
        // serializer committed. Resolved relative to the crate, offline, local-file
        // only. If serde_json's compact, document-order serialization ever diverges
        // from `JSON.stringify(adapter)`, this test fails loudly.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let rel = "/../../evidence/zk/zk-adapter-evidence-response.example.json";
        let path = format!("{manifest_dir}{rel}");
        let contents = std::fs::read_to_string(&path).expect("read the canonical example");
        let value: serde_json::Value =
            serde_json::from_str(&contents).expect("canonical example is JSON");
        let adapter = value
            .get("adapter")
            .expect("canonical example has an adapter");
        let stored = value
            .get("etag")
            .and_then(serde_json::Value::as_str)
            .expect("canonical example has a string etag");
        assert_eq!(
            compute_adapter_etag(adapter),
            stored,
            "Rust keccak256 of the adapter must equal the committed etag"
        );
    }

    #[test]
    fn rejects_etag_mismatch() {
        // A credible full adapter with a well-shaped but wrong (all-zero) etag.
        let outcome = validate_evidence_response(ETAG_MISMATCH);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag does not match keccak256 of the canonical adapter JSON")));
    }

    #[test]
    fn rejects_stale_etag_after_adapter_payload_change() {
        // The adapter payload was changed (a journal field) but the etag was left
        // at its old value — parity must catch the drift.
        let outcome = validate_evidence_response(ETAG_STALE_ADAPTER);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag does not match keccak256 of the canonical adapter JSON")));
    }

    #[test]
    fn rejects_noncanonical_adapter_key_ordering() {
        // Same adapter fields, re-ordered top-level keys, original etag. Because the
        // canonical payload is the adapter in document key order, the recomputed
        // keccak256 differs and parity fails — the check is order-sensitive by
        // design (it mirrors `JSON.stringify`, which is not key-sorted).
        let outcome = validate_evidence_response(ETAG_NONCANONICAL_ORDER);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag does not match keccak256 of the canonical adapter JSON")));
    }

    /// True when the outcome carries the Stage-4 keccak256 parity-mismatch problem.
    fn has_parity_problem(outcome: &ValidationOutcome) -> bool {
        outcome
            .problems
            .iter()
            .any(|p| p.contains("etag does not match keccak256"))
    }

    #[test]
    fn etag_parity_is_gated_behind_etag_shape() {
        // An uppercase-hex etag fails the shape check; the parity recompute is then
        // skipped (no second, redundant hash-mismatch problem). Deterministic and
        // specific: the shape problem is the only etag problem.
        let outcome = validate_evidence_response(ETAG_UPPERCASE);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag must match")));
        assert!(
            !has_parity_problem(&outcome),
            "parity must be skipped when the etag shape is already invalid"
        );
    }

    #[test]
    fn etag_parity_is_gated_behind_adapter_identity() {
        // When the adapter identity is wrong, parity is skipped (the identity
        // problem already covers it) — no redundant hash-mismatch problem.
        let outcome = validate_evidence_response(ADAPTER_WRONG_IDENTITY);
        assert!(!outcome.ok);
        assert!(
            !has_parity_problem(&outcome),
            "parity must be skipped when the adapter identity is invalid"
        );
    }

    #[test]
    fn iso8601_helper_accepts_both_contract_forms() {
        assert!(is_iso8601_utc("2026-01-01T00:00:00Z"));
        assert!(is_iso8601_utc("2026-01-01T00:00:00.000Z"));
        assert!(!is_iso8601_utc("2026-01-01 00:00:00Z")); // space, not 'T'
        assert!(!is_iso8601_utc("2026-01-01T00:00:00")); // missing 'Z'
        assert!(!is_iso8601_utc("not-a-timestamp"));
    }

    #[test]
    fn etag_helper_requires_lowercase_hex() {
        let lower = "0x98fb94cfd69a4c962501f10a581656437d11edd5419426c019a0bcdd628d4375";
        let upper = "0x98FB94CFD69A4C962501F10A581656437D11EDD5419426C019A0BCDD628D4375";
        let no_prefix = "98fb94cfd69a4c962501f10a581656437d11edd5419426c019a0bcdd628d4375";
        assert!(is_strong_etag(lower));
        assert!(!is_strong_etag("0x98fb")); // too short
        assert!(!is_strong_etag(upper)); // uppercase rejected
        assert!(!is_strong_etag(no_prefix)); // missing 0x
    }

    #[test]
    fn accepts_the_canonical_typescript_example() {
        // True fixture parity: the validator must accept the repo's canonical
        // evidence example owned by the TypeScript validators, resolved relative to
        // the crate (not the process CWD). Guards against the Rust contract check
        // drifting away from the real artifact shape. Offline local-file read only.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let rel = "/../../evidence/zk/zk-adapter-evidence-response.example.json";
        let path = format!("{manifest_dir}{rel}");
        let contents = std::fs::read_to_string(&path).expect("read the canonical example");
        let outcome = validate_evidence_response(&contents);
        assert!(
            outcome.ok,
            "canonical example should pass: {:?}",
            outcome.problems
        );
    }

    #[test]
    fn rejects_wrong_service_constant() {
        let outcome = validate_evidence_response(WRONG_SERVICE);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("service must be")));
    }

    #[test]
    fn rejects_status_ok_inconsistency() {
        // status 200 + ok:false — the cross-field consistency rule must fire.
        let outcome = validate_evidence_response(STATUS_OK_MISMATCH);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("ok is inconsistent with status")));
    }

    #[test]
    fn rejects_missing_limitations() {
        // The required top-level `limitations` field is absent — serde rejects it at
        // the typed-shape stage.
        let outcome = validate_evidence_response(MISSING_LIMITATIONS);
        assert!(!outcome.ok);
        assert!(outcome.problems[0].contains("shape"));
    }

    #[test]
    fn rejects_missing_regeneration() {
        let outcome = validate_evidence_response(MISSING_REGENERATION);
        assert!(!outcome.ok);
        assert!(outcome.problems[0].contains("shape"));
    }

    #[test]
    fn rejects_out_of_range_timestamp() {
        let outcome = validate_evidence_response(BAD_TIMESTAMP);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("servedAt must be an in-range ISO-8601 UTC timestamp")));
    }

    #[test]
    fn rejects_empty_etag() {
        let outcome = validate_evidence_response(EMPTY_ETAG);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("etag must be present and non-empty")));
    }

    #[test]
    fn rejects_non_object_adapter() {
        let outcome = validate_evidence_response(MALFORMED_ADAPTER);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("adapter must be a JSON object")));
    }

    #[test]
    fn rejects_adapter_missing_identity_fields() {
        let outcome = validate_evidence_response(ADAPTER_MISSING_IDENTITY);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("adapter.schema must be present")));
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("adapter.artifactType must be present")));
    }

    #[test]
    fn rejects_adapter_wrong_identity_values() {
        let outcome = validate_evidence_response(ADAPTER_WRONG_IDENTITY);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("adapter.schema must be the contract value")));
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("adapter.artifactType must be the contract value")));
    }

    #[test]
    fn status_consistency_helper_matches_2xx() {
        assert!(is_success_status(200));
        assert!(is_success_status(299));
        assert!(!is_success_status(199));
        assert!(!is_success_status(300));
        assert!(!is_success_status(500));
    }

    #[test]
    fn iso8601_helper_rejects_out_of_range_components() {
        assert!(is_iso8601_utc("2026-12-31T23:59:59Z"));
        assert!(!is_iso8601_utc("2026-13-01T00:00:00Z")); // month 13
        assert!(!is_iso8601_utc("2026-00-01T00:00:00Z")); // month 00
        assert!(!is_iso8601_utc("2026-01-32T00:00:00Z")); // day 32
        assert!(!is_iso8601_utc("2026-01-01T24:00:00Z")); // hour 24
        assert!(!is_iso8601_utc("2026-01-01T00:60:00Z")); // minute 60
        assert!(!is_iso8601_utc("2026-01-01T00:00:60Z")); // second 60
    }
}
