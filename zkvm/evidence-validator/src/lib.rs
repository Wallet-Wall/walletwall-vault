//! Offline, deterministic evidence-shape validator — Phase 1 scaffold.
//!
//! SCAFFOLD / OFFLINE ONLY.
//!
//! This library takes a committed evidence JSON artifact (already loaded into a
//! string by the caller) and checks its deterministic *shape* against the
//! `walletwall.zk-adapter-evidence-response.v1` response contract documented in
//! `docs/ZK_Adapter_Evidence_Endpoint.md` and pinned by
//! `evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json`.
//!
//! What this validates (shape only):
//!   * every required top-level field is present and well-typed,
//!   * no unknown top-level fields are present (`deny_unknown_fields`,
//!     mirroring the schema's `additionalProperties: false`),
//!   * the fixed-constant fields hold their contract values,
//!   * `servedAt` is an ISO-8601 UTC timestamp of the contracted form,
//!   * `etag` is a `0x` + 64 lowercase-hex string,
//!   * `limitations` is a non-empty array of non-empty strings,
//!   * `regeneration` carries a non-empty `command` and `deterministic == true`.
//!
//! What this deliberately does NOT do:
//!   * It does NOT recompute or verify the keccak256 `etag`. No cryptographic
//!     truth claim is made or checked here; the TypeScript `validate:zk-response`
//!     pass remains the authoritative `etag == keccak256(adapter)` cross-check.
//!   * It does NOT validate the embedded `adapter` in depth (only that it is a
//!     JSON object); deep adapter validation stays in TypeScript.
//!   * It performs NO network I/O, NO prover execution, NO SP1 SDK build, NO
//!     signing, NO key access, and NO chain access.
//!
//! See `docs/Rust_Evidence_Tooling_Scaffold.md` and the Phase 1 section of
//! `docs/Rust_Implementation_Path.md`.

// This scaffold has no need for `unsafe`; forbid it outright so the boundary is
// machine-checked, not just documented.
#![forbid(unsafe_code)]

use serde::Deserialize;

/// Contract constants for `walletwall.zk-adapter-evidence-response.v1`.
pub const EXPECTED_SCHEMA: &str = "walletwall.zk-adapter-evidence-response.v1";
pub const EXPECTED_SERVICE: &str = "walletwall-zk-adapter-evidence-demo";
pub const EXPECTED_MODE: &str = "spike-non-production";
pub const EXPECTED_CONTENT_TYPE: &str = "application/json";
pub const EXPECTED_STATUS: u64 = 200;

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
            return ValidationOutcome::failure(format!("input is not valid JSON: {err}"));
        }
    };

    // Stage 2 — enforce required fields, field types, and the closed top-level
    // shape (`deny_unknown_fields`). serde stops at the first structural problem.
    let parsed: EvidenceResponse = match serde_json::from_value(value) {
        Ok(parsed) => parsed,
        Err(err) => {
            return ValidationOutcome::failure(format!(
                "input does not match the zk-adapter-evidence-response.v1 shape: {err}"
            ));
        }
    };

    // Stage 3 — collect every contract-value problem; do not stop at the first.
    let mut problems: Vec<String> = Vec::new();

    if parsed.schema != EXPECTED_SCHEMA {
        problems.push(format!(
            "schema must be \"{EXPECTED_SCHEMA}\", found \"{}\"",
            parsed.schema
        ));
    }
    if parsed.service != EXPECTED_SERVICE {
        problems.push(format!(
            "service must be \"{EXPECTED_SERVICE}\", found \"{}\"",
            parsed.service
        ));
    }
    if parsed.mode != EXPECTED_MODE {
        problems.push(format!(
            "mode must be \"{EXPECTED_MODE}\", found \"{}\"",
            parsed.mode
        ));
    }
    if parsed.status != EXPECTED_STATUS {
        problems.push(format!(
            "status must be {EXPECTED_STATUS}, found {}",
            parsed.status
        ));
    }
    if !parsed.ok {
        problems.push("ok must be true".to_string());
    }
    if parsed.content_type != EXPECTED_CONTENT_TYPE {
        problems.push(format!(
            "contentType must be \"{EXPECTED_CONTENT_TYPE}\", found \"{}\"",
            parsed.content_type
        ));
    }
    if !is_iso8601_utc(&parsed.served_at) {
        problems.push(format!(
            "servedAt must be an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SS[.mmm]Z), found \"{}\"",
            parsed.served_at
        ));
    }
    if !is_strong_etag(&parsed.etag) {
        problems.push(format!(
            "etag must match ^0x[0-9a-f]{{64}}$, found \"{}\"",
            parsed.etag
        ));
    }
    if !parsed.adapter.is_object() {
        problems.push("adapter must be a JSON object".to_string());
    }
    if parsed.limitations.is_empty() {
        problems.push("limitations must be a non-empty array".to_string());
    } else if let Some(index) = parsed
        .limitations
        .iter()
        .position(|item| item.trim().is_empty())
    {
        problems.push(format!("limitations[{index}] must be a non-empty string"));
    }
    if parsed.regeneration.command.trim().is_empty() {
        problems.push("regeneration.command must be a non-empty string".to_string());
    }
    if !parsed.regeneration.deterministic {
        problems.push("regeneration.deterministic must be true".to_string());
    }

    ValidationOutcome {
        ok: problems.is_empty(),
        problems,
    }
}

/// `^0x[0-9a-f]{64}$` — a strong lowercase-hex content-hash ETag.
///
/// This is a SHAPE check only. It deliberately does NOT recompute keccak256 or
/// assert that the hash is correct for the embedded adapter.
fn is_strong_etag(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Accept exactly `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.mmmZ` — the two
/// forms the contract's `servedAt` pattern allows. Structural check only; it does
/// not validate calendar ranges (e.g. month 13 is not rejected here).
fn is_iso8601_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    let has_millis = match bytes.len() {
        20 => false,
        24 => true,
        _ => return false,
    };

    let fixed_ok = all_ascii_digits(bytes, 0, 4) // YYYY
        && bytes[4] == b'-'
        && all_ascii_digits(bytes, 5, 2) // MM
        && bytes[7] == b'-'
        && all_ascii_digits(bytes, 8, 2) // DD
        && bytes[10] == b'T'
        && all_ascii_digits(bytes, 11, 2) // HH
        && bytes[13] == b':'
        && all_ascii_digits(bytes, 14, 2) // MM
        && bytes[16] == b':'
        && all_ascii_digits(bytes, 17, 2); // SS
    if !fixed_ok {
        return false;
    }

    if has_millis {
        bytes[19] == b'.' && all_ascii_digits(bytes, 20, 3) && bytes[23] == b'Z'
    } else {
        bytes[19] == b'Z'
    }
}

/// True when `bytes[start..start + len]` are all ASCII digits. Callers guarantee
/// the range is in bounds.
fn all_ascii_digits(bytes: &[u8], start: usize, len: usize) -> bool {
    bytes[start..start + len].iter().all(u8::is_ascii_digit)
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

    #[test]
    fn accepts_the_valid_fixture() {
        let outcome = validate_evidence_response(VALID);
        assert!(
            outcome.ok,
            "expected the valid fixture to pass, got problems: {:?}",
            outcome.problems
        );
        assert!(outcome.problems.is_empty());
    }

    #[test]
    fn rejects_malformed_json() {
        let outcome = validate_evidence_response(MALFORMED);
        assert!(!outcome.ok);
        assert!(
            outcome.problems[0].contains("not valid JSON"),
            "got: {:?}",
            outcome.problems
        );
    }

    #[test]
    fn rejects_missing_required_field() {
        // `etag` is absent — serde rejects it at the typed-shape stage.
        let outcome = validate_evidence_response(MISSING_ETAG);
        assert!(!outcome.ok);
        assert!(
            outcome.problems[0].contains("shape"),
            "got: {:?}",
            outcome.problems
        );
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        // An extra top-level key is rejected by `deny_unknown_fields`.
        let outcome = validate_evidence_response(UNKNOWN_FIELD);
        assert!(!outcome.ok);
        assert!(
            outcome.problems[0].contains("shape"),
            "got: {:?}",
            outcome.problems
        );
    }

    #[test]
    fn rejects_wrong_schema_constant() {
        let outcome = validate_evidence_response(WRONG_SCHEMA);
        assert!(!outcome.ok);
        assert!(outcome.problems.iter().any(|p| p.contains("schema must be")));
    }

    #[test]
    fn rejects_bad_etag() {
        let outcome = validate_evidence_response(BAD_ETAG);
        assert!(!outcome.ok);
        assert!(outcome.problems.iter().any(|p| p.contains("etag must match")));
    }

    #[test]
    fn rejects_empty_limitations() {
        let outcome = validate_evidence_response(EMPTY_LIMITATIONS);
        assert!(!outcome.ok);
        assert!(outcome
            .problems
            .iter()
            .any(|p| p.contains("limitations must be a non-empty array")));
    }

    #[test]
    fn rejects_wrong_status() {
        let outcome = validate_evidence_response(WRONG_STATUS);
        assert!(!outcome.ok);
        assert!(outcome.problems.iter().any(|p| p.contains("status must be")));
    }

    #[test]
    fn loads_the_valid_fixture_from_disk() {
        // Exercises the on-disk read path the CLI uses, with a checked-in local
        // fixture resolved relative to the crate, not the process CWD.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/zk-adapter-evidence-response.valid.json"
        );
        let contents = std::fs::read_to_string(path).expect("read the valid fixture from disk");
        assert!(validate_evidence_response(&contents).ok);
    }

    #[test]
    fn etag_check_is_shape_only_not_a_keccak_recompute() {
        // The validator accepts ANY 0x + 64-lowercase-hex string; it does not (and
        // must not) assert the etag equals keccak256(adapter). That cross-check
        // stays in the TypeScript `validate:zk-response` pass. Swapping in a
        // different well-shaped etag must therefore still be shape-valid.
        assert!(validate_evidence_response(VALID).ok);
        let swapped = VALID.replace(
            "0x98fb94cfd69a4c962501f10a581656437d11edd5419426c019a0bcdd628d4375",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(validate_evidence_response(&swapped).ok);
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
        assert!(is_strong_etag(
            "0x98fb94cfd69a4c962501f10a581656437d11edd5419426c019a0bcdd628d4375"
        ));
        assert!(!is_strong_etag("0x98FB")); // too short
        assert!(!is_strong_etag(
            "0x98FB94CFD69A4C962501F10A581656437D11EDD5419426C019A0BCDD628D4375"
        )); // uppercase
        assert!(!is_strong_etag(
            "98fb94cfd69a4c962501f10a581656437d11edd5419426c019a0bcdd628d4375"
        )); // missing 0x
    }
}
