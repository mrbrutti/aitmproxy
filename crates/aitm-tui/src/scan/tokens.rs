//! The Scan surface's vocabulary (fix round G, G23): the wire tokens of
//! the contract enums the four tabs spell on screen, the severity order
//! every per-severity table is indexed by, and the one serde reader for an
//! enum with no hand-written table. The wire spelling is the operator
//! spelling throughout (spec D11); the static tables are pinned to the
//! serde names by a unit test.

use aitm_poc::Severity;
use aitm_scan_model::{BySeverity, Confidence, IssueStatus, LaneKind};
use serde::Serialize;

/// The five severities in header order, gravest first (spec D11). Every
/// per-severity table of the crate ([`severity_counts`], the Jobs tab's bar
/// glyphs) is indexed like this.
pub const SEVERITY_ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// A severity's wire token (`"high"`): the wire spelling is the operator
/// spelling throughout the tab. Pinned to the serde names by a unit test.
pub fn severity_token(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// A confidence's wire token (`"firm"`).
pub fn confidence_token(c: Confidence) -> &'static str {
    match c {
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Certain => "certain",
    }
}

/// A lane's wire token (`"l4_packet"`).
pub fn lane_token(l: LaneKind) -> &'static str {
    match l {
        LaneKind::Http => "http",
        LaneKind::Ws => "ws",
        LaneKind::L4Packet => "l4_packet",
        LaneKind::L4Stream => "l4_stream",
    }
}

/// An issue status's wire token (`"false_positive"`).
pub fn status_token(s: IssueStatus) -> &'static str {
    match s {
        IssueStatus::Open => "open",
        IssueStatus::Confirmed => "confirmed",
        IssueStatus::FalsePositive => "false_positive",
    }
}

/// The header label of a severity (`CRITICAL`, `HIGH`, ...).
pub fn severity_header(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// The tally's five counts in [`SEVERITY_ORDER`] order: the one walk of a
/// `BySeverity` the headers and the Jobs tab's severity bar share, read
/// through [`count_of`].
pub fn severity_counts(b: &BySeverity) -> [u64; 5] {
    SEVERITY_ORDER.map(|s| count_of(b, s))
}

/// The `by_severity` count for `s`: the one exhaustive match from a
/// severity to its tally field, so a new severity fails to compile here.
pub fn count_of(b: &BySeverity, s: Severity) -> u64 {
    match s {
        Severity::Critical => b.critical,
        Severity::High => b.high,
        Severity::Medium => b.medium,
        Severity::Low => b.low,
        Severity::Info => b.info,
    }
}

/// A contract value's wire token (`"json_value"`, `"url"`,
/// `"fewer_false_negatives"`), read off serde, so the screen spells it as
/// the contract does: the reader for the enums with no static table (the
/// insertion kinds, the profile rings). A value that does not serialise to
/// a string (none in the contract) reads `?`.
pub(crate) fn wire_token<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_scan_model::InsertionKind;
    use serde_json::json;

    #[test]
    fn headers_and_counts_follow_the_tally() {
        let b = BySeverity {
            high: 1,
            medium: 1,
            ..Default::default()
        };
        let labels: Vec<String> = SEVERITY_ORDER
            .iter()
            .map(|s| format!("{} {}", severity_header(*s), count_of(&b, *s)))
            .collect();
        assert_eq!(
            labels,
            vec!["CRITICAL 0", "HIGH 1", "MEDIUM 1", "LOW 0", "INFO 0"]
        );
        assert_eq!(severity_counts(&b), [0, 1, 1, 0, 0]);
    }

    /// Fix round D, D11: the static tokens are the serde names, variant for
    /// variant, so the filter arguments and the row cells never drift from
    /// the contract.
    #[test]
    fn static_tokens_match_the_serde_names() {
        for s in SEVERITY_ORDER {
            assert_eq!(severity_token(s), wire_token(&s));
            assert_eq!(severity_header(s), severity_token(s).to_ascii_uppercase());
        }
        for c in [Confidence::Tentative, Confidence::Firm, Confidence::Certain] {
            assert_eq!(confidence_token(c), wire_token(&c));
        }
        for l in [
            LaneKind::Http,
            LaneKind::Ws,
            LaneKind::L4Packet,
            LaneKind::L4Stream,
        ] {
            assert_eq!(lane_token(l), wire_token(&l));
        }
        for st in [
            IssueStatus::Open,
            IssueStatus::Confirmed,
            IssueStatus::FalsePositive,
        ] {
            assert_eq!(status_token(st), wire_token(&st));
        }
        assert_eq!(wire_token(&InsertionKind::WsJsonValue), "ws_json_value");
        assert_eq!(
            wire_token(&json!({"a": 1})),
            "?",
            "a non-string value reads `?`"
        );
    }
}
