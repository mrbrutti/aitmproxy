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
/// `aitm_core::redact::scrub_text_wide` is the wide reading of the shared
/// secret vocabulary (PR #199): it catches `sid`/`jwt`/`auth`-style pairs that
/// the plain `scrub_text` lets through, so every call site widens with it
/// (T1b plan, Task 19).
pub fn scrub(text: &str) -> String {
    aitm_core::redact::scrub_text_wide(text)
}

/// The serde wire token of a value, unquoted (`InsertionKind::Query` →
/// `query`, `LaneKind::L4Packet` → `l4_packet`).
///
/// The one helper behind every enum-to-token in the engine, so a point id, a
/// catalogue selector and an issue report can never spell a variant three
/// ways. A value that serialises to something other than a string (a number,
/// a map) is its JSON text; a value that cannot be serialised at all is empty,
/// so no caller can panic on a model change.
pub fn wire_token<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(token)) => token,
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

/// The default port of the four schemes the engine knows an origin by, or
/// `None` for anything else.
pub fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

/// Split `host[:port]`, keeping a bracketed IPv6 literal intact. A tail that is
/// not all digits, or does not fit a `u16`, is not a port: the authority is
/// returned whole with `None`.
pub fn split_authority(authority: &str) -> (&str, Option<u16>) {
    let tail = match authority.rfind(']') {
        Some(bracket) => &authority[bracket + 1..],
        None => authority,
    };
    match tail.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let cut = authority.len() - port.len() - 1;
            (&authority[..cut], port.parse().ok())
        }
        _ => (authority, None),
    }
}

/// The origin normal form over an already-split `(scheme, authority)`:
/// `scheme://host[:port]`, lowercased, with the scheme's default port elided
/// (`http`/`ws` 80, `https`/`wss` 443) and any other port kept.
///
/// No validation beyond that: this is for a flow the proxy already captured,
/// whose scheme and authority are what they are. An operator-written origin
/// goes through [`normalize_origin`], which refuses what is not an origin and
/// then lands in exactly this form, so the two compare byte for byte.
pub fn origin_key(scheme: &str, authority: &str) -> String {
    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.to_ascii_lowercase();
    let (host, port) = split_authority(&authority);
    match port {
        Some(port) if Some(port) != default_port(&scheme) => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    }
}

/// An operator-written origin in the one normal form ([`origin_key`]'s), or a
/// message naming what made the input not an origin.
///
/// Accepted: `http`, `https`, `ws` and `wss`, a host (an IPv6 literal keeps
/// its brackets), an optional port, an optional trailing slash, surrounding
/// whitespace. The scheme and host are lowercased and the scheme's default
/// port dropped, because `http://h:80` and `http://h` are one origin and the
/// scanner must not treat them as two. Refused, naming the part: userinfo, a
/// path, a query, a fragment, any other scheme, no scheme, no host — an origin
/// carries none of those, and silently dropping one would scan something other
/// than what the operator wrote.
pub fn normalize_origin(input: &str) -> Result<String, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("an origin is required, but it was empty".to_string());
    }
    let url = url::Url::parse(raw).map_err(|e| format!("`{raw}` is not an origin: {e}"))?;
    let scheme = url.scheme();
    if default_port(scheme).is_none() {
        return Err(format!(
            "`{raw}` is not an origin: scheme `{scheme}` is not `http`, `https`, `ws` or `wss`"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("`{raw}` is not an origin: it carries userinfo"));
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| format!("`{raw}` is not an origin: it has no host"))?;
    if !matches!(url.path(), "" | "/") {
        return Err(format!(
            "`{raw}` is not an origin: it has the path `{}`",
            url.path()
        ));
    }
    if url.query().is_some() {
        return Err(format!("`{raw}` is not an origin: it has a query string"));
    }
    if url.fragment().is_some() {
        return Err(format!("`{raw}` is not an origin: it has a fragment"));
    }
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Ok(origin_key(scheme, &authority))
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

    // ---- the one origin normal form (wave-2/3 quality fix) ------------------

    /// The one normal form every module compares origins in: scheme and host
    /// lowercased, the scheme's default port elided for all four schemes, an
    /// explicit non-default port kept, an IPv6 literal's brackets kept, the
    /// trailing slash dropped.
    #[test]
    fn normalize_origin_shape_table() {
        let table = [
            ("HTTP://Example.test:8080/", "http://example.test:8080"),
            ("https://example.test/", "https://example.test"),
            ("  http://example.test/  ", "http://example.test"),
            ("http://h:80", "http://h"),
            ("https://h:443", "https://h"),
            ("ws://h:80", "ws://h"),
            ("wss://h:443", "wss://h"),
            ("ws://h:8081", "ws://h:8081"),
            ("WSS://H:8443/", "wss://h:8443"),
            ("https://h:80", "https://h:80"),
            ("http://[::1]:8080", "http://[::1]:8080"),
            ("https://[2001:DB8::1]:443", "https://[2001:db8::1]"),
            ("http://[::1]", "http://[::1]"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ];
        for (input, want) in table {
            assert_eq!(
                normalize_origin(input).as_deref(),
                Ok(want),
                "normalize_origin({input:?})"
            );
        }
    }

    /// What is not an origin is refused with a message naming the part that
    /// made it one: userinfo, a path, a query, a fragment, an unknown scheme,
    /// no scheme, no host, nothing at all.
    #[test]
    fn normalize_origin_refuses_non_origins_naming_the_part() {
        let refused = [
            ("http://u:p@h/", "userinfo"),
            ("http://h/path", "path"),
            ("http://h/?q=1", "query"),
            ("http://h/#frag", "fragment"),
            ("ftp://h", "scheme"),
            ("http://", "host"),
            ("", "empty"),
        ];
        for (input, part) in refused {
            let err = normalize_origin(input).expect_err(input);
            assert!(
                err.contains(part),
                "refusal for {input:?} does not name {part:?}: {err}"
            );
        }
        assert!(
            normalize_origin("example.test").is_err(),
            "a bare host is not an origin"
        );
    }

    /// `origin_key` is the same table over an already-split `(scheme,
    /// authority)`, with no validation beyond lowercasing and port elision.
    #[test]
    fn origin_key_elides_default_ports_for_all_four_schemes() {
        assert_eq!(origin_key("HTTPS", "Ex.test:443"), "https://ex.test");
        assert_eq!(origin_key("http", "ex.test:80"), "http://ex.test");
        assert_eq!(origin_key("ws", "ex.test:80"), "ws://ex.test");
        assert_eq!(origin_key("wss", "ex.test:443"), "wss://ex.test");
        assert_eq!(origin_key("http", "ex.test:443"), "http://ex.test:443");
        assert_eq!(origin_key("http", "ex.test:8080"), "http://ex.test:8080");
        assert_eq!(origin_key("http", "[::1]:80"), "http://[::1]");
        assert_eq!(origin_key("http", "[::1]:8080"), "http://[::1]:8080");
        assert_eq!(origin_key("http", "TARGET.TEST"), "http://target.test");
        assert_eq!(
            normalize_origin("HTTP://Target.Test:80/").as_deref(),
            Ok(origin_key("http", "target.test").as_str()),
            "a profile origin and a flow's authority meet in one form"
        );
    }

    /// `split_authority` keeps a bracketed IPv6 literal whole and only reads a
    /// port that is all digits.
    #[test]
    fn split_authority_handles_ipv6_and_odd_ports() {
        assert_eq!(split_authority("h:8080"), ("h", Some(8080)));
        assert_eq!(split_authority("h"), ("h", None));
        assert_eq!(split_authority("[::1]:8080"), ("[::1]", Some(8080)));
        assert_eq!(split_authority("[::1]"), ("[::1]", None));
        assert_eq!(split_authority("h:"), ("h:", None));
        assert_eq!(split_authority("h:abc"), ("h:abc", None));
        assert_eq!(split_authority("h:99999"), ("h", None));
    }

    /// `wire_token` is the serde wire form of a value, unquoted: the one helper
    /// behind every `<enum> → token` in the engine.
    #[test]
    fn wire_token_is_the_unquoted_serde_form() {
        use aitm_scan_model::{InsertionKind, LaneKind};
        assert_eq!(wire_token(&InsertionKind::Query), "query");
        assert_eq!(wire_token(&InsertionKind::BodyParam), "body_param");
        assert_eq!(wire_token(&LaneKind::Http), "http");
        assert_eq!(wire_token(&LaneKind::L4Packet), "l4_packet");
        assert_eq!(wire_token(&aitm_poc::Severity::High), "high");
        assert_eq!(wire_token(&7u8), "7", "a non-string value is its JSON text");
        assert_eq!(wire_token(&"plain"), "plain", "a string is not quoted");
    }
}
