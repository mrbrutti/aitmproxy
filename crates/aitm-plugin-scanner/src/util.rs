//! Small helpers shared by every scanner v2 module.
//!
//! One home for the four things every module of the engine would otherwise
//! re-invent: the clock, the id shapes of spec D5/D6, the on-disk layout of
//! spec D11, and the single scrubbing entry point. Nothing here does I/O
//! beyond reading the clock.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Now, in milliseconds since the Unix epoch — the timestamp unit of every
/// scanner wire field (`started_at`, `finished_at`, `first_seen`, ...).
///
/// A clock before the epoch (only reachable on a badly misconfigured host)
/// reads as `0` rather than panicking: a scanner job never aborts on the clock.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// The first eight lowercase hex digits of a fresh v4 UUID — the random tail
/// both id shapes below are built from.
///
/// Eight hex digits are 32 bits of randomness, **not** a collision-free id:
/// the birthday bound puts a repeat at roughly one in 65 000 after as many
/// mints. The store that keeps the id is the one place that can tell, so it
/// checks a fresh id against what it already holds (in memory and on disk)
/// and re-mints on a collision; nothing here or in a caller may assume
/// uniqueness from this function alone.
fn short_hex() -> String {
    let mut s = uuid::Uuid::new_v4().simple().to_string();
    s.truncate(8);
    s
}

/// A fresh job id, `scan-<8 hex>` (spec D5).
///
/// Not collision-free (see [`short_hex`]): the job registry that admits a job
/// under this id must check it against the jobs it holds and re-mint on a
/// collision, as the issue store does for [`issue_id`].
pub fn job_id() -> String {
    format!("scan-{}", short_hex())
}

/// A fresh issue id, `issue-<8 hex>` (spec D6).
///
/// Not collision-free (see [`short_hex`]): `IssueStore::upsert` checks a
/// candidate against the issues it holds in memory and on disk and re-mints
/// on a collision (up to its `MAX_ID_ATTEMPTS`) rather than overwrite another
/// issue's file.
pub fn issue_id() -> String {
    format!("issue-{}", short_hex())
}

/// Where a kind of scanner state lives: `<findings_dir>/scan/<sub>` (spec D11).
///
/// `sub` is one of `jobs`, `issues`, `profiles`. The path is only built here;
/// the caller creates the directory when it writes.
pub fn scan_dir(findings_dir: &Path, sub: &str) -> PathBuf {
    findings_dir.join("scan").join(sub)
}

/// The scanner's one scrubbing entry point: every excerpt, evidence string,
/// error and push payload the engine emits goes through it, so a credential a
/// probe echoed back never reaches an issue, a log or the bus.
///
/// This is the one line Task 19 of the T1b plan flips to
/// `aitm_core::redact::scrub_text_wide` once PR #199's wider vocabulary is on
/// `main`; every call site then widens with it.
pub fn scrub(text: &str) -> String {
    aitm_core::redact::scrub_text(text)
}

/// Map a `serde_json::Value` onto the bus [`aitm_core::Value`].
///
/// An integer stays an `Int`, any other number is a `Float`, and a number with
/// neither form is `Null` — a value is never invented.
pub fn json_to_value(v: serde_json::Value) -> aitm_core::Value {
    match v {
        serde_json::Value::Null => aitm_core::Value::Null,
        serde_json::Value::Bool(b) => aitm_core::Value::Bool(b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(aitm_core::Value::Int)
            .or_else(|| n.as_f64().map(aitm_core::Value::Float))
            .unwrap_or(aitm_core::Value::Null),
        serde_json::Value::String(s) => aitm_core::Value::Str(s),
        serde_json::Value::Array(items) => {
            aitm_core::Value::Array(items.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => aitm_core::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, json_to_value(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Spec D5/D6: job ids are `scan-<8 hex>` and issue ids `issue-<8 hex>`, and
    /// two calls never collide.
    #[test]
    fn ids_have_the_wire_shape() {
        let job = job_id();
        let rest = job.strip_prefix("scan-").expect("the `scan-` prefix");
        assert_eq!(rest.len(), 8, "job id {job}");
        assert!(
            rest.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "job id {job} is not lowercase hex"
        );

        let issue = issue_id();
        let rest = issue.strip_prefix("issue-").expect("the `issue-` prefix");
        assert_eq!(rest.len(), 8, "issue id {issue}");
        assert!(
            rest.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "issue id {issue} is not lowercase hex"
        );

        assert_ne!(job_id(), job_id());
        assert_ne!(issue_id(), issue_id());
    }

    /// Spec D11: scanner state lives under `<findings.dir>/scan/<sub>`.
    #[test]
    fn scan_dir_joins_scan_then_sub() {
        assert_eq!(
            scan_dir(Path::new("/f"), "jobs"),
            PathBuf::from("/f/scan/jobs")
        );
        assert_eq!(
            scan_dir(Path::new("/f"), "issues"),
            PathBuf::from("/f/scan/issues")
        );
    }

    /// The one scrubbing helper every scanner site calls: a token in an excerpt
    /// never reaches an issue, a push line or a log.
    #[test]
    fn scrub_masks_a_token() {
        let out = scrub("Authorization: Bearer abc");
        assert!(!out.contains("abc"), "token survived scrubbing: {out}");
    }

    /// `now_ms` is epoch milliseconds, not seconds or nanoseconds.
    #[test]
    fn now_ms_is_epoch_milliseconds() {
        // 2020-01-01T00:00:00Z .. 2100-01-01T00:00:00Z in milliseconds.
        let now = now_ms();
        assert!(
            (1_577_836_800_000..4_102_444_800_000).contains(&now),
            "now_ms() = {now} is not epoch milliseconds"
        );
    }

    /// `json_to_value` maps every `serde_json` variant onto the bus `Value`.
    #[test]
    fn json_to_value_maps_every_variant() {
        use aitm_core::Value;
        assert_eq!(json_to_value(serde_json::json!(null)), Value::Null);
        assert_eq!(json_to_value(serde_json::json!(true)), Value::Bool(true));
        assert_eq!(json_to_value(serde_json::json!(42)), Value::Int(42));
        assert_eq!(json_to_value(serde_json::json!(1.5)), Value::Float(1.5));
        assert_eq!(
            json_to_value(serde_json::json!("x")),
            Value::Str("x".to_string())
        );
        assert_eq!(
            json_to_value(serde_json::json!([1, "a"])),
            Value::Array(vec![Value::Int(1), Value::Str("a".to_string())])
        );
        assert_eq!(
            json_to_value(serde_json::json!({ "k": 1 })),
            Value::Object([("k".to_string(), Value::Int(1))].into_iter().collect())
        );
    }

    /// Tester: the one scrubbing entry point survives the edges every excerpt
    /// path will feed it — empty input, text with nothing secret in it (returned
    /// unchanged, so evidence is not mangled) and a megabyte of body.
    #[test]
    fn scrub_survives_empty_plain_and_oversized_input() {
        assert_eq!(scrub(""), "");

        let plain = "GET /search?q=rust HTTP/1.1";
        assert_eq!(
            scrub(plain),
            plain,
            "text without a secret is returned as is"
        );

        let big = "x".repeat(1 << 20);
        assert_eq!(scrub(&big), big, "a plain megabyte comes back whole");
    }

    /// Tester: a secret in the middle of a large body is still masked — the
    /// scrubber is not bypassed by surrounding bulk.
    #[test]
    fn scrub_masks_a_token_buried_in_a_large_body() {
        let body = format!(
            "{}\nAuthorization: Bearer s3cr3tt0k3n\n{}",
            "a".repeat(100_000),
            "b".repeat(100_000)
        );
        let out = scrub(&body);
        assert!(!out.contains("s3cr3tt0k3n"), "token survived scrubbing");
        assert!(
            out.starts_with("aaaa") && out.ends_with("bbbb"),
            "the bulk is kept"
        );
    }

    /// Tester: numbers at the edges of the JSON model map without wrapping —
    /// a `u64` past `i64::MAX` becomes a `Float`, `i64::MIN` stays an `Int`,
    /// and deep nesting is preserved.
    #[test]
    fn json_to_value_handles_numbers_at_the_edges_and_nesting() {
        use aitm_core::Value;
        assert_eq!(
            json_to_value(serde_json::json!(u64::MAX)),
            Value::Float(u64::MAX as f64),
            "a u64 past i64::MAX is a Float, never a wrapped Int"
        );
        assert_eq!(
            json_to_value(serde_json::json!(i64::MIN)),
            Value::Int(i64::MIN)
        );
        assert_eq!(json_to_value(serde_json::json!(-0.0)), Value::Float(-0.0));
        assert_eq!(
            json_to_value(serde_json::json!([[{ "k": [null] }]])),
            Value::Array(vec![Value::Array(vec![Value::Object(
                [("k".to_string(), Value::Array(vec![Value::Null]))]
                    .into_iter()
                    .collect()
            )])])
        );
        assert_eq!(
            json_to_value(serde_json::json!({})),
            Value::Object(Default::default())
        );
        assert_eq!(json_to_value(serde_json::json!([])), Value::Array(vec![]));
    }

    /// Tester: `scan_dir` is a pure join — a relative findings dir stays
    /// relative and every documented `sub` lands under `scan/`.
    #[test]
    fn scan_dir_is_a_pure_join_for_every_documented_sub() {
        for sub in ["jobs", "issues", "profiles"] {
            assert_eq!(
                scan_dir(Path::new("findings"), sub),
                PathBuf::from(format!("findings/scan/{sub}"))
            );
        }
    }
}
