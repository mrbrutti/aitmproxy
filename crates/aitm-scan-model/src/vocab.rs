//! The closed enum vocabulary every scanner v2 wire type is built from (spec D2, D3).
//!
//! Each token here is contract: a frontend, a Rhai check and the engine all read
//! and write these exact snake_case strings. Adding a variant is a wire change.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Which lane a point, check, probe or issue belongs to.
///
/// The enum is `LaneKind` because `Lane` is the trait a lane crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    /// HTTP/1.1 and HTTP/2 requests and responses.
    Http,
    /// WebSocket handshakes and frames.
    Ws,
    /// Datagram-oriented layer 4 (UDP).
    L4Packet,
    /// Stream-oriented layer 4 (TCP).
    L4Stream,
}

/// How invasive a check or profile is allowed to be. Ordered: `Passive` is least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intensity {
    /// Observation only: no probe is sent.
    Passive,
    /// A handful of safe probes per point.
    Light,
    /// The default working intensity.
    Medium,
    /// Everything short of destructive, including slow and noisy techniques.
    Intrusive,
}

/// The time-versus-coverage dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Speed {
    /// Fewest probes; skip the slow techniques.
    Fast,
    /// The default.
    Normal,
    /// Every applicable check on every point, including low-yield ones.
    Thorough,
}

/// Which way the scheduler leans when a verdict is uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accuracy {
    /// Report more, at the cost of false positives.
    FewerFalseNegatives,
    /// The default balance.
    Normal,
    /// Report only what survives confirmation.
    FewerFalsePositives,
}

/// Where in a request a payload is inserted (spec D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsertionKind {
    /// A URL query parameter value.
    Query,
    /// A form-urlencoded body parameter value.
    BodyParam,
    /// A JSON body value, addressed by `InsertionPoint::path`.
    JsonValue,
    /// An XML element's text.
    XmlValue,
    /// An XML attribute's value.
    XmlAttr,
    /// A multipart part's value.
    MultipartValue,
    /// A multipart part's declared filename.
    MultipartFilename,
    /// A request header value.
    Header,
    /// A single cookie's value.
    Cookie,
    /// One segment of the URL path.
    PathSegment,
    /// The final path segment when it looks like a filename.
    PathFilename,
    /// A query parameter's *name* (intensity `medium` and above).
    ParamNameQuery,
    /// A body parameter's *name* (intensity `medium` and above).
    ParamNameBody,
    /// The whole body, when it is in no recognised format.
    EntireBody,
    /// A JSON value inside a WebSocket text frame.
    WsJsonValue,
    /// A whole WebSocket text frame.
    WsText,
    /// A form-encoded parameter inside a WebSocket text frame.
    WsFormParam,
    /// A WebSocket binary frame's payload.
    WsBinary,
    /// A header on the WebSocket upgrade request.
    WsHandshakeHeader,
    /// A grammar field path in an L4 message.
    L4Field,
}

impl InsertionKind {
    /// Every insertion kind, in spec D2's order. The default `audit.kinds` set.
    pub const ALL: [InsertionKind; 20] = [
        InsertionKind::Query,
        InsertionKind::BodyParam,
        InsertionKind::JsonValue,
        InsertionKind::XmlValue,
        InsertionKind::XmlAttr,
        InsertionKind::MultipartValue,
        InsertionKind::MultipartFilename,
        InsertionKind::Header,
        InsertionKind::Cookie,
        InsertionKind::PathSegment,
        InsertionKind::PathFilename,
        InsertionKind::ParamNameQuery,
        InsertionKind::ParamNameBody,
        InsertionKind::EntireBody,
        InsertionKind::WsJsonValue,
        InsertionKind::WsText,
        InsertionKind::WsFormParam,
        InsertionKind::WsBinary,
        InsertionKind::WsHandshakeHeader,
        InsertionKind::L4Field,
    ];
}

/// What a point's observed value looks like, used to aim checks at likely points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointTrait {
    /// The value parses as a URL (redirect and SSRF candidates).
    Url,
    /// The value looks like a file name or path.
    Filename,
    /// The value is numeric.
    Number,
    /// The value looks like an email address.
    Email,
    /// The value decodes as base64.
    Base64,
    /// The value parses as JSON.
    Json,
    /// The value looks like an identifier (access-control candidates).
    Id,
    /// The value carries session state; ignored by default (spec D2).
    Session,
}

/// How sure a verdict is. Ordered: `Tentative` is weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A signal that may well be noise.
    Tentative,
    /// A reproducible signal with a plausible benign explanation.
    Firm,
    /// Confirmed, typically by a control probe.
    Certain,
}

/// Roughly how many probes a check spends per point: `<=3`, `<=10`, more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCost {
    /// At most three probes per point.
    Light,
    /// At most ten probes per point.
    Medium,
    /// More than ten probes per point.
    Heavy,
}

/// The detection technique a check uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Technique {
    /// The payload comes back in the response.
    Reflected,
    /// The target reports an error that reveals the injection.
    Error,
    /// True/false payload pairs produce different responses.
    Boolean,
    /// The target's response time tracks a requested delay.
    Timing,
    /// The finding is in a protocol handshake.
    Handshake,
    /// A malformed message provokes the finding.
    Malformed,
    /// Derived from watching traffic the scanner itself caused.
    Observe,
    /// Derived from already-captured traffic; sends nothing.
    Passive,
}

/// A check run's result for one point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The check found the weakness.
    Vulnerable,
    /// The check ran and found nothing.
    Clean,
    /// The check could not decide (noise, throttling, a lost session).
    Inconclusive,
    /// The check failed to run.
    Error,
}

/// Where a check came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckOrigin {
    /// Compiled into a lane crate.
    Native,
    /// A script from the catalogue shipped with aitmproxy.
    Bundled {
        /// Repo-relative path of the script.
        path: String,
    },
    /// A script the operator wrote.
    Custom {
        /// Path of the operator's script.
        path: String,
    },
}

/// Which HTTP version a scan's probes negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersionPolicy {
    /// Let the sender negotiate (the default).
    Auto,
    /// Force HTTP/1.1.
    H1,
    /// Force HTTP/2 over TLS.
    H2,
    /// Force HTTP/2 cleartext.
    H2c,
}

/// Which probe flows a scan records into the flow store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordProbes {
    /// Only the probes that evidenced an issue (the default).
    IssuesOnly,
    /// Every probe. Loud, and heavy on the store.
    All,
}

/// An issue's triage state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueStatus {
    /// Reported, not yet triaged.
    Open,
    /// The operator confirmed it.
    Confirmed,
    /// The operator rejected it.
    FalsePositive,
}

/// The transport an L4 target speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// How hard the crawler works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlStrategy {
    /// Links only.
    Fast,
    /// Links and safe forms (the default).
    Normal,
    /// Links, forms and event handlers, to the configured depth.
    Thorough,
}

/// Whether the crawler drives a real browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseBrowser {
    /// Use one when the target needs script execution (the default).
    Auto,
    /// Always use one.
    Always,
    /// Never use one.
    Never,
}

/// Where a scan's session comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// Reuse the session observed in a captured flow (the default).
    Observed,
    /// Scan unauthenticated.
    None,
}

/// What a job does when its session stops working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnLost {
    /// Stop the job (the default): results past this point are not trustworthy.
    Stop,
    /// Carry on unauthenticated.
    Continue,
}

/// How a payload combines with the point's existing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    /// Replace the value.
    Replace,
    /// Put the payload before the value.
    Prefix,
    /// Put the payload after the value.
    Suffix,
}

/// The eleven error codes a `scan.*` verb can fail with (spec D3).
///
/// `h2_not_negotiated` is a sender error, not a verb error code, and is not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanErrorCode {
    /// No such job, issue or profile.
    NotFound,
    /// The concurrent-job ceiling is reached.
    Busy,
    /// A target is outside the configured scope.
    OutOfScope,
    /// The agent policy refused the verb.
    RefusedAgent,
    /// The L4 guard refused the target.
    RefusedL4,
    /// A requested lane is not in this build.
    LaneUnavailable,
    /// The profile failed to parse or validate.
    InvalidProfile,
    /// A selector names a check that does not exist.
    UnknownCheck,
    /// The verb needs an operator confirmation it did not get.
    ConfirmRequired,
    /// The job was cancelled.
    Cancelled,
    /// A requested value exceeded a configured ceiling.
    Clamped,
}

impl ScanErrorCode {
    /// The wire token, identical to the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanErrorCode::NotFound => "not_found",
            ScanErrorCode::Busy => "busy",
            ScanErrorCode::OutOfScope => "out_of_scope",
            ScanErrorCode::RefusedAgent => "refused_agent",
            ScanErrorCode::RefusedL4 => "refused_l4",
            ScanErrorCode::LaneUnavailable => "lane_unavailable",
            ScanErrorCode::InvalidProfile => "invalid_profile",
            ScanErrorCode::UnknownCheck => "unknown_check",
            ScanErrorCode::ConfirmRequired => "confirm_required",
            ScanErrorCode::Cancelled => "cancelled",
            ScanErrorCode::Clamped => "clamped",
        }
    }

    /// Split a `scan: <code>: <message>` error string into its code and message.
    ///
    /// Returns `None` for any string that is not in that form, including one whose
    /// code is not a known token, so a caller can fall back to the raw text.
    pub fn parse_message(msg: &str) -> Option<(ScanErrorCode, &str)> {
        let rest = msg.strip_prefix("scan: ")?;
        let (code, detail) = rest.split_once(": ")?;
        Some((code.parse().ok()?, detail))
    }
}

impl fmt::Display for ScanErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScanErrorCode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "not_found" => Ok(ScanErrorCode::NotFound),
            "busy" => Ok(ScanErrorCode::Busy),
            "out_of_scope" => Ok(ScanErrorCode::OutOfScope),
            "refused_agent" => Ok(ScanErrorCode::RefusedAgent),
            "refused_l4" => Ok(ScanErrorCode::RefusedL4),
            "lane_unavailable" => Ok(ScanErrorCode::LaneUnavailable),
            "invalid_profile" => Ok(ScanErrorCode::InvalidProfile),
            "unknown_check" => Ok(ScanErrorCode::UnknownCheck),
            "confirm_required" => Ok(ScanErrorCode::ConfirmRequired),
            "cancelled" => Ok(ScanErrorCode::Cancelled),
            "clamped" => Ok(ScanErrorCode::Clamped),
            other => Err(anyhow::anyhow!("unknown scan error code: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_kind_wire_tokens() {
        assert_eq!(
            serde_json::to_string(&LaneKind::L4Packet).expect("serializes"),
            "\"l4_packet\""
        );
        assert_eq!(
            serde_json::from_str::<LaneKind>("\"l4_stream\"").expect("deserializes"),
            LaneKind::L4Stream
        );
    }

    #[test]
    fn intensity_is_ordered() {
        assert!(Intensity::Passive < Intensity::Light);
        assert!(Intensity::Light < Intensity::Medium);
        assert!(Intensity::Medium < Intensity::Intrusive);
    }

    #[test]
    fn confidence_is_ordered() {
        assert!(Confidence::Tentative < Confidence::Firm);
        assert!(Confidence::Firm < Confidence::Certain);
    }

    #[test]
    fn insertion_kind_all_round_trips() {
        assert_eq!(InsertionKind::ALL.len(), 20);
        for kind in InsertionKind::ALL {
            let json = serde_json::to_string(&kind).expect("serializes");
            let back: InsertionKind = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(back, kind, "round trip of {json}");
        }
        assert_eq!(
            serde_json::to_string(&InsertionKind::WsHandshakeHeader).expect("serializes"),
            "\"ws_handshake_header\""
        );
    }

    /// Tester: `ALL` is the whole D2 vocabulary, in order, with no duplicate and
    /// no omission — a length check alone would still pass if a variant were
    /// dropped and another listed twice, and `audit.kinds` defaults to this list.
    #[test]
    fn insertion_kind_all_is_the_d2_vocabulary() {
        let tokens: Vec<String> = InsertionKind::ALL
            .iter()
            .map(|k| {
                serde_json::to_string(k)
                    .expect("serializes")
                    .replace('"', "")
            })
            .collect();
        assert_eq!(
            tokens,
            vec![
                "query",
                "body_param",
                "json_value",
                "xml_value",
                "xml_attr",
                "multipart_value",
                "multipart_filename",
                "header",
                "cookie",
                "path_segment",
                "path_filename",
                "param_name_query",
                "param_name_body",
                "entire_body",
                "ws_json_value",
                "ws_text",
                "ws_form_param",
                "ws_binary",
                "ws_handshake_header",
                "l4_field",
            ]
        );
        let distinct: std::collections::HashSet<&InsertionKind> =
            InsertionKind::ALL.iter().collect();
        assert_eq!(distinct.len(), InsertionKind::ALL.len(), "no duplicate");
    }

    /// Tester: every error code's serde token, `as_str` and `FromStr` agree, so a
    /// UI that matches on the token of a `scan: <code>: <message>` string and a
    /// UI that matches on the JSON token match the same thing.
    #[test]
    fn every_error_code_token_agrees_across_serde_display_and_from_str() {
        let codes = [
            ScanErrorCode::NotFound,
            ScanErrorCode::Busy,
            ScanErrorCode::OutOfScope,
            ScanErrorCode::RefusedAgent,
            ScanErrorCode::RefusedL4,
            ScanErrorCode::LaneUnavailable,
            ScanErrorCode::InvalidProfile,
            ScanErrorCode::UnknownCheck,
            ScanErrorCode::ConfirmRequired,
            ScanErrorCode::Cancelled,
            ScanErrorCode::Clamped,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            let token = code.as_str();
            assert!(seen.insert(token), "{token} listed twice");
            assert_eq!(
                serde_json::to_string(&code).expect("serializes"),
                format!("\"{token}\""),
                "serde token of {token}"
            );
            assert_eq!(code.to_string(), token);
            assert_eq!(token.parse::<ScanErrorCode>().expect("parses"), code);
            assert_eq!(
                ScanErrorCode::parse_message(&format!("scan: {token}: why")),
                Some((code, "why"))
            );
        }
        assert_eq!(seen.len(), 11);
    }

    /// Tester: `parse_message` is fed raw `anyhow` text from anywhere, so every
    /// malformed shape must fall back to `None` rather than mis-parse. The empty
    /// string, a bare prefix, an unknown code, a missing message separator and a
    /// code buried mid-string are all refused; a message containing `": "` keeps
    /// its whole tail.
    #[test]
    fn parse_message_refuses_malformed_input() {
        for junk in [
            "",
            " ",
            "scan:",
            "scan: ",
            "scan: busy",
            "scan: busy:",
            "scan: nonsense: why",
            "scan:busy: why",
            "SCAN: busy: why",
            "prefixed scan: busy: why",
            ": : ",
        ] {
            assert_eq!(
                ScanErrorCode::parse_message(junk),
                None,
                "{junk:?} must not parse"
            );
        }
        assert_eq!(
            ScanErrorCode::parse_message("scan: out_of_scope: host: port not in scope"),
            Some((ScanErrorCode::OutOfScope, "host: port not in scope")),
            "only the first separator splits"
        );
    }

    #[test]
    fn check_origin_is_kind_tagged() {
        assert_eq!(
            serde_json::to_string(&CheckOrigin::Bundled {
                path: "a.rhai".into()
            })
            .expect("serializes"),
            r#"{"kind":"bundled","path":"a.rhai"}"#
        );
        assert_eq!(
            serde_json::to_string(&CheckOrigin::Native).expect("serializes"),
            r#"{"kind":"native"}"#
        );
    }

    #[test]
    fn error_code_parse_message() {
        assert_eq!(
            ScanErrorCode::parse_message("scan: lane_unavailable: ws not built"),
            Some((ScanErrorCode::LaneUnavailable, "ws not built"))
        );
        assert_eq!(ScanErrorCode::parse_message("boom"), None);
    }
}
